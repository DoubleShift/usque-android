package api

// Account and device management endpoints, ported from upstream usque
// (cmd/account + api/cloudflare.go): the /account sub-API is keyed to the
// device's own id/token and covers the license key shared by all devices.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
)

// GetAccount fetches account information (type, dates, license, WARP+ state)
// for the device's own WARP account.
func GetAccount(deviceId string, deviceToken string) (*models.Account, error) {
	req, err := http.NewRequest(http.MethodGet, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)

	resp, err := apiHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := readAPIBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return nil, fmt.Errorf("failed to parse error response: %v", err)
		}
		return nil, fmt.Errorf("failed to get account: %s (API: %s)", resp.Status, apiErr.ErrorsAsString("; "))
	}

	var respData models.Account
	if err := json.Unmarshal(body, &respData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}
	return &respData, nil
}

// UpdateLicenceKey binds a new license key to the current device. The device
// then shares the WARP account (and WARP+ status) linked to that key.
func UpdateLicenceKey(deviceId string, deviceToken string, licenceKey string) error {
	jsonData, err := json.Marshal(map[string]string{"license": licenceKey})
	if err != nil {
		return fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest(http.MethodPut, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)

	resp, err := apiHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := readAPIBody(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return fmt.Errorf("failed to update license: %s", resp.Status)
		}
		return fmt.Errorf("failed to update license: %s (API: %s)", resp.Status, apiErr.ErrorsAsString("; "))
	}
	return nil
}

// DeleteLicenceKey removes the license key binding from the current device,
// returning it to the free tier.
func DeleteLicenceKey(deviceId string, deviceToken string) error {
	req, err := http.NewRequest(http.MethodDelete, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)

	resp, err := apiHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := readAPIBody(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return fmt.Errorf("failed to remove license: %s", resp.Status)
		}
		return fmt.Errorf("failed to remove license: %s (API: %s)", resp.Status, apiErr.ErrorsAsString("; "))
	}
	return nil
}

// GetDevices lists all devices bound to the same license key as this device.
func GetDevices(deviceId string, deviceToken string) (*models.Devices, error) {
	req, err := http.NewRequest(http.MethodGet, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account/devices", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)

	resp, err := apiHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := readAPIBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return nil, fmt.Errorf("failed to get devices: %s", resp.Status)
		}
		return nil, fmt.Errorf("failed to get devices: %s (API: %s)", resp.Status, apiErr.ErrorsAsString("; "))
	}

	var respData models.Devices
	if err := json.Unmarshal(body, &respData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}
	return &respData, nil
}
