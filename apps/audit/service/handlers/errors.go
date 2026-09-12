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

package handlers

import (
	"errors"

	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/pitabwire/frame/v2/data"
	"gorm.io/gorm"
)

// Response metadata keys naming the failing rule without echoing content.
const (
	metaReason = "Audit-Reject-Reason"
	metaField  = "Audit-Reject-Field"
)

// toConnectError maps business and repository errors to Connect codes.
func toConnectError(err error) error {
	if err == nil {
		return nil
	}
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		return err
	}
	var verr *business.ValidationError
	if errors.As(err, &verr) {
		code := connect.CodeInvalidArgument
		if verr.Reason == business.ReasonServiceBinding {
			code = connect.CodePermissionDenied
		}
		out := connect.NewError(code, verr)
		out.Meta().Set(metaReason, verr.Reason)
		if verr.Field != "" {
			out.Meta().Set(metaField, verr.Field)
		}
		return out
	}
	switch {
	case errors.Is(err, business.ErrBacklogExceeded):
		out := connect.NewError(connect.CodeResourceExhausted, err)
		out.Meta().Set("Retry-After", "5")
		return out
	case errors.Is(err, business.ErrManifestServiceMismatch):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, business.ErrSearchWindowRequired):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, repository.ErrAlreadyRetiredOrMissing), errors.Is(err, business.ErrKeyNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, gorm.ErrRecordNotFound), data.ErrorIsNoRows(err):
		return connect.NewError(connect.CodeNotFound, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
