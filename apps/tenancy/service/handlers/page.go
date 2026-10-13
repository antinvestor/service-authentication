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

	"buf.build/gen/go/antinvestor/tenancy/connectrpc/go/v2/tenancy/v1/tenancyv1connect"
	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
)

func (prtSrv *TenancyServer) CreatePage(
	ctx context.Context,
	req *tenancyv1.CreatePageRequest,
) (*tenancyv1.CreatePageResponse, error) {
	page, err := prtSrv.PageBusiness.CreatePage(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.CreatePageResponse{Data: page}, nil
}

func (prtSrv *TenancyServer) ListPage(
	ctx context.Context,
	req *tenancyv1.ListPageRequest,
	stream tenancyv1connect.TenancyServiceListPageServerStream,
) error {
	pages, err := prtSrv.PageBusiness.ListPages(ctx, req.GetPartitionId())
	if err != nil {
		return prtSrv.toAPIError(err)
	}
	return stream.Send(&tenancyv1.ListPageResponse{Data: pages})
}

func (prtSrv *TenancyServer) UpdatePage(
	ctx context.Context,
	req *tenancyv1.UpdatePageRequest,
) (*tenancyv1.UpdatePageResponse, error) {
	page, err := prtSrv.PageBusiness.UpdatePage(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.UpdatePageResponse{Data: page}, nil
}

func (prtSrv *TenancyServer) GetPage(
	ctx context.Context,
	req *tenancyv1.GetPageRequest,
) (*tenancyv1.GetPageResponse, error) {
	page, err := prtSrv.PageBusiness.GetPage(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.GetPageResponse{Data: page}, nil
}

func (prtSrv *TenancyServer) RemovePage(
	ctx context.Context,
	req *tenancyv1.RemovePageRequest,
) (*tenancyv1.RemovePageResponse, error) {
	err := prtSrv.PageBusiness.RemovePage(ctx, req)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return &tenancyv1.RemovePageResponse{
		Succeeded: true,
	}, nil
}
