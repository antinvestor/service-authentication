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

package loginhistory

import (
	"context"
	"errors"
	"net/http"

	authv1 "buf.build/gen/go/antinvestor/authentication/protocolbuffers/go/authentication/v1"
	"connectrpc.com/connect/v2"
	"github.com/antinvestor/service-authentication/apps/default/service/handlers"
	"github.com/antinvestor/service-authentication/apps/default/service/sessionproof"
)

// GenesisProofs issues and verifies genesis session proofs. The
// authentication server implements it, so the Connect RPCs and the REST
// endpoints share one code path.
type GenesisProofs interface {
	IssueGenesisSessionProof(ctx context.Context, in handlers.GenesisProofIssueInput) (*sessionproof.Issued, error)
	VerifyGenesisSessionProof(ctx context.Context, in handlers.GenesisProofVerifyInput) (*handlers.GenesisProofVerdict, error)
}

// WithGenesisProofs enables the genesis session proof RPCs.
func (s *LoginHistoryServer) WithGenesisProofs(proofs GenesisProofs) *LoginHistoryServer {
	s.genesisProofs = proofs
	return s
}

// IssueGenesisSessionProof mints a proof bound to the caller's live session.
func (s *LoginHistoryServer) IssueGenesisSessionProof(
	ctx context.Context,
	req *authv1.IssueGenesisSessionProofRequest,
) (*authv1.IssueGenesisSessionProofResponse, error) {
	if s.genesisProofs == nil {
		return nil, connect.NewError(connect.CodeUnavailable, "genesis session proofs are not configured")
	}
	issued, err := s.genesisProofs.IssueGenesisSessionProof(ctx, handlers.GenesisProofIssueInput{
		PubkeyHash:  req.GetPubkeyHash(),
		DeviceKeyID: req.GetDeviceKeyId(),
		DeviceID:    req.GetDeviceId(),
	})
	if err != nil {
		return nil, genesisProofError(err)
	}
	return &authv1.IssueGenesisSessionProofResponse{
		Token:       issued.Token,
		KeyId:       issued.Claims.KeyID,
		Algorithm:   issued.Claims.Algorithm,
		Nonce:       issued.Claims.Nonce,
		IssuedAt:    issued.Claims.IssuedAt,
		ExpiresAt:   issued.Claims.ExpiresAt,
		BindingHash: issued.BindingHash,
		Audience:    issued.Claims.Audience,
	}, nil
}

// VerifyGenesisSessionProof checks a proof and optionally spends its nonce.
// An invalid proof is answered with valid=false and a reason, not an error.
func (s *LoginHistoryServer) VerifyGenesisSessionProof(
	ctx context.Context,
	req *authv1.VerifyGenesisSessionProofRequest,
) (*authv1.VerifyGenesisSessionProofResponse, error) {
	if s.genesisProofs == nil {
		return nil, connect.NewError(connect.CodeUnavailable, "genesis session proofs are not configured")
	}
	verdict, err := s.genesisProofs.VerifyGenesisSessionProof(ctx, handlers.GenesisProofVerifyInput{
		Token:       req.GetToken(),
		ProfileID:   req.GetProfileId(),
		DeviceID:    req.GetDeviceId(),
		PubkeyHash:  req.GetPubkeyHash(),
		DeviceKeyID: req.GetDeviceKeyId(),
		Consume:     req.GetConsume(),
	})
	if err != nil {
		return nil, genesisProofError(err)
	}
	out := &authv1.VerifyGenesisSessionProofResponse{
		Valid:       verdict.Valid,
		Reason:      verdict.Reason,
		BindingHash: verdict.BindingHash,
	}
	if c := verdict.Claims; c != nil {
		out.Claims = &authv1.GenesisSessionProofClaims{
			Version: c.Version, KeyId: c.KeyID, Algorithm: c.Algorithm,
			ProfileId: c.ProfileID, DeviceId: c.DeviceID, PubkeyHash: c.PubkeyHash,
			DeviceKeyId: c.DeviceKeyID, Nonce: c.Nonce, IssuedAt: c.IssuedAt,
			ExpiresAt: c.ExpiresAt, SessionId: c.SessionID, TenantId: c.TenantID,
			PartitionId: c.PartitionID, Audience: c.Audience,
		}
	}
	return out, nil
}

// genesisProofError maps a refusal's HTTP status to the matching Connect code.
func genesisProofError(err error) error {
	var refusal *handlers.GenesisProofError
	if !errors.As(err, &refusal) {
		return connect.NewError(connect.CodeInternal, "genesis session proof failed")
	}
	code := connect.CodeInternal
	switch refusal.Status {
	case http.StatusBadRequest:
		code = connect.CodeInvalidArgument
	case http.StatusUnauthorized:
		code = connect.CodeUnauthenticated
	case http.StatusForbidden:
		code = connect.CodePermissionDenied
	case http.StatusServiceUnavailable:
		code = connect.CodeUnavailable
	}
	return connect.NewError(code, refusal.Reason)
}
