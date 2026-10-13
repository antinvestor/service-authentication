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

	"buf.build/gen/go/antinvestor/authentication/connectrpc/go/v2/authentication/v1/authenticationv1connect"
	authv1 "buf.build/gen/go/antinvestor/authentication/protocolbuffers/go/authentication/v1"
	"connectrpc.com/connect/v2"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/pitabwire/frame/v3/data"
	"github.com/pitabwire/frame/v3/security/authorizer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// LoginHistoryServer implements the AuthenticationServiceHandler Connect RPC interface.
type LoginHistoryServer struct {
	loginEventRepo repository.LoginEventRepository
	loginRepo      repository.LoginRepository
	genesisProofs  GenesisProofs
	authenticationv1connect.UnimplementedAuthenticationServiceHandler
}

// NewLoginHistoryServer creates a new server with injected repositories.
func NewLoginHistoryServer(
	loginEventRepo repository.LoginEventRepository,
	loginRepo repository.LoginRepository,
) *LoginHistoryServer {
	return &LoginHistoryServer{
		loginEventRepo: loginEventRepo,
		loginRepo:      loginRepo,
	}
}

// GetLoginEvent retrieves a single login event by ID.
func (s *LoginHistoryServer) GetLoginEvent(
	ctx context.Context,
	req *authv1.GetLoginEventRequest,
) (*authv1.GetLoginEventResponse, error) {
	event, err := s.loginEventRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, toAPIError(err)
	}
	if event == nil {
		return nil, connect.NewError(connect.CodeNotFound, "login event not found")
	}

	login, _ := s.loginRepo.GetByProfileID(ctx, event.ProfileID)

	return &authv1.GetLoginEventResponse{
		Data: loginEventToProto(event, login),
	}, nil
}

// ListLoginEvents queries login events with filtering and pagination.
func (s *LoginHistoryServer) ListLoginEvents(
	ctx context.Context,
	req *authv1.ListLoginEventsRequest,
	stream authenticationv1connect.AuthenticationServiceListLoginEventsServerStream,
) error {
	filter := &LoginEventFilter{
		ProfileID: req.GetProfileId(),
		ClientID:  req.GetClientId(),
		Source:    req.GetSource(),
		DeviceID:  req.GetDeviceId(),
		Limit:     int(req.GetCount()),
		Cursor:    req.GetPage(),
	}

	if req.GetStartDate() != nil {
		t := req.GetStartDate().AsTime()
		filter.StartDate = &t
	}
	if req.GetEndDate() != nil {
		t := req.GetEndDate().AsTime()
		filter.EndDate = &t
	}

	events, err := s.listLoginEvents(ctx, filter)
	if err != nil {
		return toAPIError(err)
	}

	result := make([]*authv1.LoginEventObject, 0, len(events))
	for _, e := range events {
		result = append(result, loginEventToProto(e, nil))
	}

	return stream.Send(&authv1.ListLoginEventsResponse{
		Data: result,
	})
}

// toAPIError maps authorization and storage errors to Connect errors.
// connect v2 sends only a *connect.Error's message to the client.
func toAPIError(err error) error {
	if err == nil {
		return nil
	}
	if cerr := (*connect.Error)(nil); errors.As(err, &cerr) {
		return cerr
	}
	var permErr *authorizer.PermissionDeniedError
	if errors.As(err, &permErr) ||
		errors.Is(err, authorizer.ErrInvalidSubject) || errors.Is(err, authorizer.ErrInvalidObject) {
		return authorizer.ToConnectError(err)
	}
	if data.ErrorIsNoRows(err) {
		return connect.NewError(connect.CodeNotFound, err.Error()).WithCause(err)
	}
	// Downstream gRPC failures (Keto, for one) keep their code; gRPC and
	// Connect share the numbering.
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return connect.NewError(connect.Code(st.Code()), err.Error()).WithCause(err)
	}
	return data.ErrorConvertToAPI(err)
}

func loginEventToProto(event *models.LoginEvent, login *models.Login) *authv1.LoginEventObject {
	obj := &authv1.LoginEventObject{
		Id:          event.GetID(),
		TenantId:    event.TenantID,
		PartitionId: event.PartitionID,
		ProfileId:   event.ProfileID,
		ClientId:    event.ClientID,
		ContactId:   event.ContactID,
		DeviceId:    event.DeviceID,
		IpAddress:   event.IP,
		UserAgent:   event.Client,
		Status:      int32(event.Status),
	}

	// Set source from the Login record if available, otherwise leave empty
	if login != nil {
		obj.Source = login.Source
	}

	// Set properties
	if event.Properties != nil {
		details, err := structpb.NewStruct(event.Properties)
		if err == nil {
			obj.Properties = details
		}
	}

	// Set timestamps
	if !event.CreatedAt.IsZero() {
		obj.CreatedAt = timestamppb.New(event.CreatedAt)
	}

	return obj
}
