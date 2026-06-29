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

	"buf.build/gen/go/antinvestor/authentication/connectrpc/go/authentication/v1/authenticationv1connect"
	authv1 "buf.build/gen/go/antinvestor/authentication/protocolbuffers/go/authentication/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/default/service/models"
	"github.com/antinvestor/service-authentication/apps/default/service/repository"
	"github.com/pitabwire/frame/v2/data"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// LoginHistoryServer implements the AuthenticationServiceHandler Connect RPC interface.
type LoginHistoryServer struct {
	loginEventRepo repository.LoginEventRepository
	loginRepo      repository.LoginRepository
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
	req *connect.Request[authv1.GetLoginEventRequest],
) (*connect.Response[authv1.GetLoginEventResponse], error) {
	event, err := s.loginEventRepo.GetByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toAPIError(err)
	}
	if event == nil {
		return nil, status.Error(codes.NotFound, "login event not found")
	}

	login, _ := s.loginRepo.GetByProfileID(ctx, event.ProfileID)

	return connect.NewResponse(&authv1.GetLoginEventResponse{
		Data: loginEventToProto(event, login),
	}), nil
}

// ListLoginEvents queries login events with filtering and pagination.
func (s *LoginHistoryServer) ListLoginEvents(
	ctx context.Context,
	req *connect.Request[authv1.ListLoginEventsRequest],
	stream *connect.ServerStream[authv1.ListLoginEventsResponse],
) error {
	filter := &LoginEventFilter{
		ProfileID: req.Msg.GetProfileId(),
		ClientID:  req.Msg.GetClientId(),
		Source:    req.Msg.GetSource(),
		DeviceID:  req.Msg.GetDeviceId(),
		Limit:     int(req.Msg.GetCount()),
		Cursor:    req.Msg.GetPage(),
	}

	if req.Msg.GetStartDate() != nil {
		t := req.Msg.GetStartDate().AsTime()
		filter.StartDate = &t
	}
	if req.Msg.GetEndDate() != nil {
		t := req.Msg.GetEndDate().AsTime()
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

func toAPIError(err error) error {
	grpcError, ok := status.FromError(err)
	if ok {
		return grpcError.Err()
	}
	if data.ErrorIsNoRows(err) {
		return status.Error(codes.NotFound, err.Error())
	}
	return grpcError.Err()
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
