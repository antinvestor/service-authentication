// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package business

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	aconfig "github.com/antinvestor/service-authentication/apps/audit/config"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/util"
	"gorm.io/gorm"
)

// Errors surfaced by the key provider.
var (
	ErrKeyRefMissing     = errors.New("AUDIT_SIGNING_KEY_REF and AUDIT_SIGNING_KEY_ID are required")
	ErrActiveKeyRetired  = errors.New("active signing key is retired")
	ErrPublicKeyMismatch = errors.New("loaded private key does not match the stored public key")
	ErrKeyNotFound       = errors.New("signing key not found")
)

// KeyProvider resolves the active signer and public keys for verification.
type KeyProvider interface {
	// Active returns the current signer or an error when it is unusable
	// (retired, mismatched, unresolvable).
	Active() (*Signer, error)
	// ActiveKeyID returns the configured key id regardless of health.
	ActiveKeyID() string
	// Public returns the verifying key for keyID.
	Public(ctx context.Context, keyID string) (ed25519.PublicKey, error)
	// Reload re-reads the key material and the key row.
	Reload(ctx context.Context) error
	// Retire marks keyID retired. The active key may be retired; Active()
	// then fails until the process is rolled with a new key id.
	Retire(ctx context.Context, keyID string) (*models.AuditSigningKey, error)
	// List returns all key rows, oldest first.
	List(ctx context.Context) ([]*models.AuditSigningKey, error)
	// Seed inserts the active key's public half when absent (setup Job).
	Seed(ctx context.Context) error
}

type keyProvider struct {
	cfg  *aconfig.AuditConfig
	repo repository.SigningKeyRepository

	signer atomic.Pointer[Signer]
	state  atomic.Pointer[keyState]

	mu    sync.RWMutex
	cache map[string]ed25519.PublicKey
}

type keyState struct {
	err error
}

// NewKeyProvider loads the configured key and validates it against the key
// registry. It fails when the reference is unresolvable or when the stored
// public key differs. A missing key row
// is tolerated so the setup Job can call Seed; the runtime calls Reload
// after seeding is guaranteed.
func NewKeyProvider(ctx context.Context, cfg *aconfig.AuditConfig, repo repository.SigningKeyRepository) (KeyProvider, error) {
	if cfg.SigningKeyRef == "" || cfg.SigningKeyID == "" {
		return nil, ErrKeyRefMissing
	}
	kp := &keyProvider{cfg: cfg, repo: repo, cache: map[string]ed25519.PublicKey{}}
	priv, err := LoadPrivateKeyRef(cfg.SigningKeyRef, cfg.SigningKeyID, cfg.SigningKeyMountDir)
	if err != nil {
		return nil, err
	}
	signer, err := NewSigner(cfg.SigningKeyID, priv)
	if err != nil {
		return nil, err
	}
	kp.signer.Store(signer)
	kp.state.Store(&keyState{})
	if err = kp.validateAgainstRegistry(ctx); err != nil && !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}
	return kp, nil
}

// LoadPrivateKeyRef resolves a key reference to private key bytes.
//
//	file:///abs/path      → that file
//	vault://path#property → <mountDir>/<keyID> (projected by External Secrets)
func LoadPrivateKeyRef(ref, keyID, mountDir string) (ed25519.PrivateKey, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("signing key ref %q: %w", ref, err)
	}
	var path string
	switch u.Scheme {
	case "file":
		path = u.Path
		if u.Host != "" { // file://relative/path
			path = filepath.Join(u.Host, u.Path)
		}
	case "vault":
		path = filepath.Join(mountDir, keyID)
	default:
		return nil, fmt.Errorf("signing key ref %q: unsupported scheme %q", ref, u.Scheme)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signing key %q: %w", path, err)
	}
	priv, err := ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("signing key %q: %w", path, err)
	}
	return priv, nil
}

func (kp *keyProvider) validateAgainstRegistry(ctx context.Context) error {
	signer := kp.signer.Load()
	row, err := kp.repo.GetByKeyID(ctx, signer.KeyID())
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || data.ErrorIsNoRows(err) {
			kp.state.Store(&keyState{err: ErrKeyNotFound})
			return ErrKeyNotFound
		}
		return fmt.Errorf("load key row %q: %w", signer.KeyID(), err)
	}
	if !bytes.Equal(row.PublicKey, signer.Public()) {
		kp.state.Store(&keyState{err: ErrPublicKeyMismatch})
		return ErrPublicKeyMismatch
	}
	if row.RetiredAt != nil {
		kp.state.Store(&keyState{err: ErrActiveKeyRetired})
		return ErrActiveKeyRetired
	}
	kp.state.Store(&keyState{})
	kp.mu.Lock()
	kp.cache[row.KeyID] = ed25519.PublicKey(row.PublicKey)
	kp.mu.Unlock()
	return nil
}

func (kp *keyProvider) Active() (*Signer, error) {
	if st := kp.state.Load(); st != nil && st.err != nil {
		return nil, st.err
	}
	return kp.signer.Load(), nil
}

func (kp *keyProvider) ActiveKeyID() string { return kp.cfg.SigningKeyID }

func (kp *keyProvider) Public(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	kp.mu.RLock()
	pub, ok := kp.cache[keyID]
	kp.mu.RUnlock()
	if ok {
		return pub, nil
	}
	row, err := kp.repo.GetByKeyID(ctx, keyID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || data.ErrorIsNoRows(err) {
			return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
		}
		return nil, err
	}
	pub = ed25519.PublicKey(row.PublicKey)
	kp.mu.Lock()
	kp.cache[keyID] = pub
	kp.mu.Unlock()
	return pub, nil
}

func (kp *keyProvider) Reload(ctx context.Context) error {
	priv, err := LoadPrivateKeyRef(kp.cfg.SigningKeyRef, kp.cfg.SigningKeyID, kp.cfg.SigningKeyMountDir)
	if err != nil {
		util.Log(ctx).WithError(err).Warn("audit key reload: keeping previous key material")
	} else if signer, sErr := NewSigner(kp.cfg.SigningKeyID, priv); sErr == nil {
		kp.signer.Store(signer)
	}
	return kp.validateAgainstRegistry(ctx)
}

func (kp *keyProvider) Retire(ctx context.Context, keyID string) (*models.AuditSigningKey, error) {
	now := time.Now().UTC()
	if err := kp.repo.Retire(ctx, keyID, now); err != nil {
		return nil, err
	}
	if keyID == kp.cfg.SigningKeyID {
		kp.state.Store(&keyState{err: ErrActiveKeyRetired})
	}
	return kp.repo.GetByKeyID(ctx, keyID)
}

func (kp *keyProvider) List(ctx context.Context) ([]*models.AuditSigningKey, error) {
	return kp.repo.List(ctx)
}

func (kp *keyProvider) Seed(ctx context.Context) error {
	signer := kp.signer.Load()
	_, err := kp.repo.GetByKeyID(ctx, signer.KeyID())
	if err == nil {
		return kp.validateAgainstRegistry(ctx)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) && !data.ErrorIsNoRows(err) {
		return fmt.Errorf("seed key %q: %w", signer.KeyID(), err)
	}
	row := &models.AuditSigningKey{
		KeyID: signer.KeyID(), Algorithm: models.AlgorithmEd25519,
		PublicKey: []byte(signer.Public()), ValidFrom: time.Now().UTC(),
	}
	if err = kp.repo.Create(ctx, row); err != nil {
		return fmt.Errorf("seed key %q: %w", signer.KeyID(), err)
	}
	util.Log(ctx).WithField("key_id", signer.KeyID()).Info("audit signing key registered")
	return kp.validateAgainstRegistry(ctx)
}
