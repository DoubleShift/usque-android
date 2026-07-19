package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
)

// apiHTTPClient is a shared *http.Client used for all Cloudflare API calls.
// The default http.DefaultClient has no timeout, which lets a stuck request
// pin a goroutine and an in-flight response buffer forever — a real concern
// on long-running Android processes. We also cap response bodies so a
// misbehaving server can't force us to allocate unbounded memory.
var apiHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	// Transport left as DefaultTransport so we still benefit from the
	// global keep-alive connection pool to api.cloudflareclient.com.
}

// maxAPIResponseBytes caps how much of an API response body we will buffer
// into memory. The /reg and PATCH /reg/{id} responses are well under 10 KiB
// in practice, so 1 MiB is a generous safety upper bound.
const maxAPIResponseBytes = 1 << 20 // 1 MiB

// readAPIBody reads a Cloudflare API response body with a hard size cap so we
// don't blow up memory if the server misbehaves. The cap does not apply to
// streaming paths — only to the small JSON envelopes used here.
func readAPIBody(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxAPIResponseBytes))
}

// Register creates a new user account by registering a WireGuard public key and generating a random Android-like device identifier.
// The WireGuard private key isn't stored anywhere, therefore it won't be usable. It's sole purpose is to mimic the Android app's registration process.
//
// This function sends a POST request to the API to register a new user and returns the created account data.
//
// Parameters:
//   - model: string - The device model string to register. (e.g., "PC")
//   - locale: string - The user's locale. (e.g., "en-US")
//   - jwt: string - Team token to register.
//   - acceptTos: bool - Whether the user accepts the Terms of Service (TOS). If false, the user will be prompted to accept.
//
// Returns:
//   - models.AccountData: The account data returned from the registration process.
//   - error:              An error if registration fails at any step.
//
// Example:
//
//	account, err := Register("PC", "en-US", "", false)
//	if err != nil {
//	    log.Fatalf("Registration failed: %v", err)
//	}
func Register(model, locale, jwt string, acceptTos bool) (models.AccountData, error) {
	wgKey, err := internal.GenerateRandomWgPubkey()
	if err != nil {
		return models.AccountData{}, fmt.Errorf("failed to generate wg key: %v", err)
	}
	serial, err := internal.GenerateRandomAndroidSerial()
	if err != nil {
		return models.AccountData{}, fmt.Errorf("failed to generate serial: %v", err)
	}

	if !acceptTos {
		fmt.Print("You must accept the Terms of Service (https://www.cloudflare.com/application/terms/) to register. Do you agree? (y/n): ")
		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			return models.AccountData{}, fmt.Errorf("failed to read user input: %v", err)
		}
		if response != "y" {
			return models.AccountData{}, fmt.Errorf("user did not accept TOS")
		}
	}

	data := models.Registration{
		Key:       wgKey,
		InstallID: "",
		FcmToken:  "",
		Tos:       internal.TimeAsCfString(time.Now()),
		Model:     model,
		Serial:    serial,
		OsVersion: "",
		KeyType:   internal.KeyTypeWg,
		TunType:   internal.TunTypeWg,
		Locale:    locale,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return models.AccountData{}, fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest("POST", internal.ApiUrl+"/"+internal.ApiVersion+"/reg", bytes.NewBuffer(jsonData))
	if err != nil {
		return models.AccountData{}, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}

	if jwt != "" {
		req.Header.Set("CF-Access-Jwt-Assertion", jwt)
	}

	resp, err := apiHTTPClient.Do(req)
	if err != nil {
		return models.AccountData{}, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return models.AccountData{}, fmt.Errorf("failed to register: %v", resp.Status)
	}

	var accountData models.AccountData
	// Use the sized reader to cap worst-case allocation if the server
	// misbehaves; the normal /reg response is small.
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIResponseBytes)).Decode(&accountData); err != nil {
		return models.AccountData{}, fmt.Errorf("failed to decode response: %v", err)
	}

	return accountData, nil
}

// EnrollKey updates an existing user account with a new MASQUE public key.
//
// This function sends a PATCH request to update the user's account with a new key.
//
// Parameters:
//   - accountData: models.AccountData - The account data of the user being updated.
//   - pubKey: []byte - The new MASQUE public key in binary format.
//   - deviceName: string - The name of the device to enroll. (optional)
//
// Returns:
//   - models.AccountData: The updated account data.
//   - error:              An error if the update process fails.
//
// Example:
//
//	updatedAccount, apiErr, err := EnrollKey(account, pubKey, "PC")
//	if err != nil {
//	    log.Fatalf("Key enrollment failed: %v", err)
//	}
func EnrollKey(accountData models.AccountData, pubKey []byte, deviceName string) (models.AccountData, *models.APIError, error) {
	deviceUpdate := models.DeviceUpdate{
		Key:     base64.StdEncoding.EncodeToString(pubKey),
		KeyType: internal.KeyTypeMasque,
		TunType: internal.TunTypeMasque,
	}

	if deviceName != "" {
		deviceUpdate.Name = deviceName
	}

	jsonData, err := json.Marshal(deviceUpdate)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest("PATCH", internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+accountData.ID, bytes.NewBuffer(jsonData))
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+accountData.Token)

	resp, err := apiHTTPClient.Do(req)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := readAPIBody(resp.Body)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return models.AccountData{}, nil, fmt.Errorf("failed to parse error response: %v", err)
		}
		return models.AccountData{}, &apiErr, fmt.Errorf("failed to update: %s", resp.Status)
	}

	if err := json.Unmarshal(body, &accountData); err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return accountData, nil, nil
}
