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
	"context"
	"fmt"

	"buf.build/gen/go/antinvestor/audit/connectrpc/go/audit/v1/auditv1connect"
	auditv1 "buf.build/gen/go/antinvestor/audit/protocolbuffers/go/audit/v1"
	"connectrpc.com/connect"
	"github.com/antinvestor/service-authentication/apps/audit/service/business"
	"github.com/antinvestor/service-authentication/apps/audit/service/models"
	"github.com/antinvestor/service-authentication/apps/audit/service/repository"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AuditServer implements the generated AuditServiceHandler Connect RPC interface.
type AuditServer struct {
	svc           *frame.Service
	auditBusiness business.AuditBusiness
	auditv1connect.UnimplementedAuditServiceHandler
}

// NewAuditServer creates a new AuditServer with injected dependencies.
func NewAuditServer(ctx context.Context, service *frame.Service, signer *business.ChainSigner) *AuditServer {
	dbPool := service.DatastoreManager().GetPool(ctx, datastore.DefaultPoolName)
	repo := repository.NewAuditEntryRepository(dbPool)
	auditBiz := business.NewAuditBusiness(repo, signer)

	return &AuditServer{
		svc:           service,
		auditBusiness: auditBiz,
	}
}

// NewAuditServerWithPool creates a new AuditServer with an explicit DB pool.
func NewAuditServerWithPool(service *frame.Service, dbPool pool.Pool, signer *business.ChainSigner) *AuditServer {
	repo := repository.NewAuditEntryRepository(dbPool)
	auditBiz := business.NewAuditBusiness(repo, signer)

	return &AuditServer{
		svc:           service,
		auditBusiness: auditBiz,
	}
}

func (as *AuditServer) toAPIError(err error) error {
	grpcError, ok := status.FromError(err)
	if ok {
		return grpcError.Err()
	}
	if data.ErrorIsNoRows(err) {
		return status.Error(codes.NotFound, err.Error())
	}
	return grpcError.Err()
}

// CreateAuditEntry appends a new entry to the audit trail.
func (as *AuditServer) CreateAuditEntry(
	ctx context.Context,
	req *connect.Request[auditv1.CreateAuditEntryRequest],
) (*connect.Response[auditv1.CreateAuditEntryResponse], error) {
	input := requestToInput(req.Msg)

	entry, err := as.auditBusiness.CreateEntry(ctx, input)
	if err != nil {
		return nil, as.toAPIError(err)
	}

	return connect.NewResponse(&auditv1.CreateAuditEntryResponse{
		Data: entryToProto(entry),
	}), nil
}

// BatchCreateAuditEntries appends multiple entries atomically.
func (as *AuditServer) BatchCreateAuditEntries(
	ctx context.Context,
	req *connect.Request[auditv1.BatchCreateAuditEntriesRequest],
) (*connect.Response[auditv1.BatchCreateAuditEntriesResponse], error) {
	inputs := make([]*business.CreateEntryInput, 0, len(req.Msg.GetEntries()))
	for _, e := range req.Msg.GetEntries() {
		inputs = append(inputs, requestToInput(e))
	}

	entries, err := as.auditBusiness.BatchCreateEntries(ctx, inputs)
	if err != nil {
		return nil, as.toAPIError(err)
	}

	result := make([]*auditv1.AuditEntryObject, 0, len(entries))
	for _, e := range entries {
		result = append(result, entryToProto(e))
	}

	return connect.NewResponse(&auditv1.BatchCreateAuditEntriesResponse{
		Data: result,
	}), nil
}

// GetAuditEntry retrieves a single audit entry by ID.
func (as *AuditServer) GetAuditEntry(
	ctx context.Context,
	req *connect.Request[auditv1.GetAuditEntryRequest],
) (*connect.Response[auditv1.GetAuditEntryResponse], error) {
	entry, err := as.auditBusiness.GetEntry(ctx, req.Msg.GetId())
	if err != nil {
		return nil, as.toAPIError(err)
	}

	return connect.NewResponse(&auditv1.GetAuditEntryResponse{
		Data: entryToProto(entry),
	}), nil
}

// ListAuditEntries queries audit entries with filtering and pagination.
func (as *AuditServer) ListAuditEntries(
	ctx context.Context,
	req *connect.Request[auditv1.ListAuditEntriesRequest],
	stream *connect.ServerStream[auditv1.ListAuditEntriesResponse],
) error {
	filter := &repository.AuditFilter{
		ProfileID:       req.Msg.GetProfileId(),
		Action:          req.Msg.GetAction(),
		ResourceType:    req.Msg.GetResourceType(),
		ResourceID:      req.Msg.GetResourceId(),
		Service:         req.Msg.GetService(),
		TargetProfileID: req.Msg.GetTargetProfileId(),
		DeviceID:        req.Msg.GetDeviceId(),
		Limit:           int(req.Msg.GetCount()),
		Cursor:          req.Msg.GetPage(),
	}

	if req.Msg.GetStartDate() != nil {
		t := req.Msg.GetStartDate().AsTime()
		filter.StartDate = &t
	}
	if req.Msg.GetEndDate() != nil {
		t := req.Msg.GetEndDate().AsTime()
		filter.EndDate = &t
	}

	entries, err := as.auditBusiness.ListEntries(ctx, filter)
	if err != nil {
		return as.toAPIError(err)
	}

	result := make([]*auditv1.AuditEntryObject, 0, len(entries))
	for _, e := range entries {
		result = append(result, entryToProto(e))
	}

	return stream.Send(&auditv1.ListAuditEntriesResponse{
		Data: result,
	})
}

// SearchAuditEntries performs free-text search across audit entries.
func (as *AuditServer) SearchAuditEntries(
	ctx context.Context,
	req *connect.Request[auditv1.SearchAuditEntriesRequest],
	stream *connect.ServerStream[auditv1.SearchAuditEntriesResponse],
) error {
	filter := &repository.AuditFilter{
		Limit:  int(req.Msg.GetCount()),
		Cursor: req.Msg.GetPage(),
	}

	if req.Msg.GetStartDate() != nil {
		t := req.Msg.GetStartDate().AsTime()
		filter.StartDate = &t
	}
	if req.Msg.GetEndDate() != nil {
		t := req.Msg.GetEndDate().AsTime()
		filter.EndDate = &t
	}

	entries, err := as.auditBusiness.SearchEntries(
		ctx,
		req.Msg.GetQuery(),
		filter.StartDate,
		filter.EndDate,
		filter.Limit,
		filter.Cursor,
	)
	if err != nil {
		return as.toAPIError(err)
	}

	result := make([]*auditv1.AuditEntryObject, 0, len(entries))
	for _, e := range entries {
		result = append(result, entryToProto(e))
	}

	return stream.Send(&auditv1.SearchAuditEntriesResponse{
		Data: result,
	})
}

// VerifyIntegrity verifies the hash chain integrity over a time range.
func (as *AuditServer) VerifyIntegrity(
	ctx context.Context,
	req *connect.Request[auditv1.VerifyIntegrityRequest],
) (*connect.Response[auditv1.VerifyIntegrityResponse], error) {
	filter := &repository.AuditFilter{}

	if req.Msg.GetStartDate() != nil {
		t := req.Msg.GetStartDate().AsTime()
		filter.StartDate = &t
	}
	if req.Msg.GetEndDate() != nil {
		t := req.Msg.GetEndDate().AsTime()
		filter.EndDate = &t
	}

	result, err := as.auditBusiness.VerifyIntegrity(ctx, filter.StartDate, filter.EndDate)
	if err != nil {
		return nil, as.toAPIError(err)
	}

	return connect.NewResponse(&auditv1.VerifyIntegrityResponse{
		Valid:               result.Valid,
		EntriesVerified:     result.EntriesVerified,
		FirstInvalidEntryId: result.FirstInvalidEntryID,
		Message:             result.Message,
	}), nil
}

// GetAuditBusiness exposes the business layer for use by other services
// within the same process (e.g., tenancy service emitting audit events).
func (as *AuditServer) GetAuditBusiness() business.AuditBusiness {
	return as.auditBusiness
}

// EmitAuditEntry is a convenience method for other in-process services
// to emit audit entries without going through RPC.
func (as *AuditServer) EmitAuditEntry(ctx context.Context, input *business.CreateEntryInput) error {
	_, err := as.auditBusiness.CreateEntry(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to emit audit entry: %w", err)
	}
	return nil
}

func requestToInput(req *auditv1.CreateAuditEntryRequest) *business.CreateEntryInput {
	var details data.JSONMap
	if req.GetDetails() != nil {
		details = req.GetDetails().AsMap()
	}

	return &business.CreateEntryInput{
		ProfileID:       req.GetProfileId(),
		Action:          req.GetAction(),
		ResourceType:    req.GetResourceType(),
		ResourceID:      req.GetResourceId(),
		Service:         req.GetService(),
		Details:         details,
		IPAddress:       req.GetIpAddress(),
		UserAgent:       req.GetUserAgent(),
		DeviceID:        req.GetDeviceId(),
		TargetProfileID: req.GetTargetProfileId(),
		TraceID:         req.GetTraceId(),
	}
}

func entryToProto(entry *models.AuditEntry) *auditv1.AuditEntryObject {
	var details *structpb.Struct
	if entry.Details != nil {
		details, _ = structpb.NewStruct(entry.Details)
	}

	obj := &auditv1.AuditEntryObject{
		Id:              entry.GetID(),
		TenantId:        entry.TenantID,
		PartitionId:     entry.PartitionID,
		ProfileId:       entry.ProfileID,
		Action:          entry.Action,
		ResourceType:    entry.ResourceType,
		ResourceId:      entry.ResourceID,
		Service:         entry.Service,
		Details:         details,
		IpAddress:       entry.IPAddress,
		UserAgent:       entry.UserAgent,
		DeviceId:        entry.DeviceID,
		TargetProfileId: entry.TargetProfileID,
		TraceId:         entry.TraceID,
		PreviousHash:    entry.PreviousHash,
		EntryHash:       entry.EntryHash,
		Signature:       entry.Signature,
	}

	if !entry.CreatedAt.IsZero() {
		obj.CreatedAt = timestamppb.New(entry.CreatedAt)
	}

	return obj
}
