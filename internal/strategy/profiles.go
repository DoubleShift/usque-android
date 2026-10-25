// Package strategy — profiles.go
//
// Per-network strategy profiles. Each network the device connects through
// (WiFi SSID or mobile carrier id, supplied by the app layer) gets a stored
// decision, so reconnecting to a known network is instant instead of
// re-probing. All profiles live in one JSON file next to config.json.
package strategy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const profilesFileName = "network_profiles.json"

// ProfileFreshFor is how long a stored profile is trusted without a re-probe.
const ProfileFreshFor = 7 * 24 * time.Hour

var profilesMu sync.Mutex

type profileStore struct {
	Profiles map[string]*NetworkProfile `json:"profiles"`
}

// NetworkProfile is the persisted probe decision for one network.
type NetworkProfile struct {
	NetworkID  string      `json:"network_id"`
	Chosen     *Candidate  `json:"chosen,omitempty"`
	Candidates []Candidate `json:"candidates"`
	VerifiedAt int64       `json:"verified_at"`
}

// Fresh reports whether the profile is recent enough to auto-connect with.
func (p *NetworkProfile) Fresh() bool {
	return p != nil && p.Chosen != nil &&
		time.Since(time.Unix(p.VerifiedAt, 0)) < ProfileFreshFor
}

func profilesPath(dir string) string {
	return filepath.Join(dir, profilesFileName)
}

func loadStore(dir string) (*profileStore, error) {
	data, err := os.ReadFile(profilesPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return &profileStore{Profiles: map[string]*NetworkProfile{}}, nil
		}
		return nil, err
	}
	var store profileStore
	if err := json.Unmarshal(data, &store); err != nil {
		// A corrupt file must not brick the app; start over.
		return &profileStore{Profiles: map[string]*NetworkProfile{}}, nil
	}
	if store.Profiles == nil {
		store.Profiles = map[string]*NetworkProfile{}
	}
	return &store, nil
}

func saveStore(dir string, store *profileStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(profilesPath(dir), data, 0600)
}

// SaveNetworkProfile persists a probe decision for networkID.
func SaveNetworkProfile(dir, networkID string, d *Decision) error {
	if networkID == "" || d == nil {
		return nil
	}
	profilesMu.Lock()
	defer profilesMu.Unlock()
	store, err := loadStore(dir)
	if err != nil {
		return err
	}
	store.Profiles[networkID] = &NetworkProfile{
		NetworkID:  networkID,
		Chosen:     d.Chosen,
		Candidates: d.Candidates,
		VerifiedAt: d.VerifiedAt,
	}
	return saveStore(dir, store)
}

// LoadNetworkProfile returns the stored profile for networkID, or nil when
// none exists (os.IsNotExist-style: not an error).
func LoadNetworkProfile(dir, networkID string) (*NetworkProfile, error) {
	if networkID == "" {
		return nil, nil
	}
	profilesMu.Lock()
	defer profilesMu.Unlock()
	store, err := loadStore(dir)
	if err != nil {
		return nil, err
	}
	return store.Profiles[networkID], nil
}

// ForgetNetworkProfile drops the stored profile for networkID (e.g. after a
// connect failure with a previously-fresh profile).
func ForgetNetworkProfile(dir, networkID string) error {
	if networkID == "" {
		return nil
	}
	profilesMu.Lock()
	defer profilesMu.Unlock()
	store, err := loadStore(dir)
	if err != nil {
		return err
	}
	if _, ok := store.Profiles[networkID]; !ok {
		return nil
	}
	delete(store.Profiles, networkID)
	return saveStore(dir, store)
}
