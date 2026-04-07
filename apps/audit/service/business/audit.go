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
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/pitabwire/frame/data"
	"github.com/pitabwire/frame/security"
)

// AuditBusiness defines the business logic interface for audit operations.
type AuditBusiness interface {
	CreateEntry(ctx context.Context, entry *CreateEntryInput) (*models.AuditEntry, error)
	BatchCreateEntries(ctx context.Context, entries []*CreateEntryInput) ([]*models.AuditEntry, error)
	GetEntry(ctx context.Context, id string) (*models.AuditEntry, error)
	ListEntries(ctx context.Context, filter *repository.AuditFilter) ([]*models.AuditEntry, error)
	SearchEntries(ctx context.Context, query string, startDate, endDate *time.Time, limit int, cursor string) ([]*models.AuditEntry, error)
	VerifyIntegrity(ctx context.Context, startDate, endDate *time.Time) (*IntegrityResult, error)
}

// CreateEntryInput contains the fields provided by the caller when creating
// an audit entry. Hash chain and signature are computed by the business layer.
type CreateEntryInput struct {
	ProfileID       string
	Action          string
	ResourceType    string
	ResourceID      string
	Service         string
	Details         data.JSONMap
	IPAddress       string
	UserAgent       string
	DeviceID        string
	TargetProfileID string
	TraceID         string
}

// IntegrityResult reports the outcome of hash chain verification.
type IntegrityResult struct {
	Valid               bool
	EntriesVerified     int64
	FirstInvalidEntryID string
	Message             string
}

type auditBusiness struct {
	repo   repository.AuditEntryRepository
	signer *ChainSigner

	// mu serialises hash chain operations per tenant to prevent race conditions
	// where two concurrent creates could read the same previous hash.
	mu sync.Mutex
}

// NewAuditBusiness creates a new audit business layer.
func NewAuditBusiness(repo repository.AuditEntryRepository, signer *ChainSigner) AuditBusiness {
	return &auditBusiness{
		repo:   repo,
		signer: signer,
	}
}

func (ab *auditBusiness) CreateEntry(ctx context.Context, input *CreateEntryInput) (*models.AuditEntry, error) {
	claims := security.ClaimsFromContext(ctx)
	tenantID := ""
	partitionID := ""
	if claims != nil {
		tenantID = claims.GetTenantID()
		partitionID = claims.GetPartitionID()
	}

	ab.mu.Lock()
	defer ab.mu.Unlock()

	previousHash, err := ab.repo.GetLatestHash(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest hash: %w", err)
	}

	entry := ab.buildEntry(tenantID, partitionID, input)
	if err := ab.signer.SignEntry(entry, previousHash); err != nil {
		return nil, fmt.Errorf("failed to sign entry: %w", err)
	}

	if err := ab.repo.Create(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to create audit entry: %w", err)
	}

	return entry, nil
}

func (ab *auditBusiness) BatchCreateEntries(ctx context.Context, inputs []*CreateEntryInput) ([]*models.AuditEntry, error) {
	claims := security.ClaimsFromContext(ctx)
	tenantID := ""
	partitionID := ""
	if claims != nil {
		tenantID = claims.GetTenantID()
		partitionID = claims.GetPartitionID()
	}

	ab.mu.Lock()
	defer ab.mu.Unlock()

	previousHash, err := ab.repo.GetLatestHash(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest hash: %w", err)
	}

	entries := make([]*models.AuditEntry, 0, len(inputs))
	for _, input := range inputs {
		entry := ab.buildEntry(tenantID, partitionID, input)
		if err := ab.signer.SignEntry(entry, previousHash); err != nil {
			return nil, fmt.Errorf("failed to sign entry: %w", err)
		}
		previousHash = entry.EntryHash
		entries = append(entries, entry)
	}

	if err := ab.repo.CreateBatch(ctx, entries); err != nil {
		return nil, fmt.Errorf("failed to create audit entries: %w", err)
	}

	return entries, nil
}

func (ab *auditBusiness) GetEntry(ctx context.Context, id string) (*models.AuditEntry, error) {
	return ab.repo.GetByID(ctx, id)
}

func (ab *auditBusiness) ListEntries(ctx context.Context, filter *repository.AuditFilter) ([]*models.AuditEntry, error) {
	return ab.repo.List(ctx, filter)
}

func (ab *auditBusiness) SearchEntries(ctx context.Context, query string, startDate, endDate *time.Time, limit int, cursor string) ([]*models.AuditEntry, error) {
	return ab.repo.Search(ctx, query, startDate, endDate, limit, cursor)
}

func (ab *auditBusiness) VerifyIntegrity(ctx context.Context, startDate, endDate *time.Time) (*IntegrityResult, error) {
	claims := security.ClaimsFromContext(ctx)
	tenantID := ""
	if claims != nil {
		tenantID = claims.GetTenantID()
	}

	const batchSize = 1000
	var totalVerified int64
	offset := 0
	previousHash := ""

	for {
		entries, err := ab.repo.ListChain(ctx, tenantID, startDate, endDate, batchSize, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to list chain entries: %w", err)
		}
		if len(entries) == 0 {
			break
		}

		for _, entry := range entries {
			// Verify the previous hash links correctly
			if entry.PreviousHash != previousHash {
				return &IntegrityResult{
					Valid:               false,
					EntriesVerified:     totalVerified,
					FirstInvalidEntryID: entry.GetID(),
					Message:             fmt.Sprintf("chain break at entry %s: expected previous_hash %q, got %q", entry.GetID(), previousHash, entry.PreviousHash),
				}, nil
			}

			// Recompute the hash and verify
			expectedHash := ab.signer.ComputeHash(entry, previousHash)
			if entry.EntryHash != expectedHash {
				return &IntegrityResult{
					Valid:               false,
					EntriesVerified:     totalVerified,
					FirstInvalidEntryID: entry.GetID(),
					Message:             fmt.Sprintf("hash mismatch at entry %s: content has been tampered with", entry.GetID()),
				}, nil
			}

			// Verify the digital signature
			if !ab.signer.VerifySignature(entry.EntryHash, entry.Signature) {
				return &IntegrityResult{
					Valid:               false,
					EntriesVerified:     totalVerified,
					FirstInvalidEntryID: entry.GetID(),
					Message:             fmt.Sprintf("invalid signature at entry %s: signature does not match entry hash", entry.GetID()),
				}, nil
			}

			previousHash = entry.EntryHash
			totalVerified++
		}

		if len(entries) < batchSize {
			break
		}
		offset += batchSize
	}

	return &IntegrityResult{
		Valid:           true,
		EntriesVerified: totalVerified,
		Message:         fmt.Sprintf("all %d entries verified successfully", totalVerified),
	}, nil
}

func (ab *auditBusiness) buildEntry(tenantID, partitionID string, input *CreateEntryInput) *models.AuditEntry {
	return &models.AuditEntry{
		BaseModel: data.BaseModel{
			TenantID:    tenantID,
			PartitionID: partitionID,
		},
		ProfileID:       input.ProfileID,
		Action:          input.Action,
		ResourceType:    input.ResourceType,
		ResourceID:      input.ResourceID,
		Service:         input.Service,
		Details:         input.Details,
		IPAddress:       input.IPAddress,
		UserAgent:       input.UserAgent,
		DeviceID:        input.DeviceID,
		TargetProfileID: input.TargetProfileID,
		TraceID:         input.TraceID,
	}
}
