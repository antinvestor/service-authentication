package handlers

import (
	"context"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"connectrpc.com/connect"
)

func (prtSrv *TenancyServer) CreatePage(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreatePageRequest],
) (*connect.Response[tenancyv1.CreatePageResponse], error) {
	page, err := prtSrv.PageBusiness.CreatePage(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.CreatePageResponse{Data: page}), nil
}

func (prtSrv *TenancyServer) ListPage(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListPageRequest],
	stream *connect.ServerStream[tenancyv1.ListPageResponse],
) error {
	pages, err := prtSrv.PageBusiness.ListPages(ctx, req.Msg.GetPartitionId())
	if err != nil {
		return prtSrv.toAPIError(err)
	}
	return stream.Send(&tenancyv1.ListPageResponse{Data: pages})
}

func (prtSrv *TenancyServer) UpdatePage(
	ctx context.Context,
	req *connect.Request[tenancyv1.UpdatePageRequest],
) (*connect.Response[tenancyv1.UpdatePageResponse], error) {
	page, err := prtSrv.PageBusiness.UpdatePage(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.UpdatePageResponse{Data: page}), nil
}

func (prtSrv *TenancyServer) GetPage(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetPageRequest],
) (*connect.Response[tenancyv1.GetPageResponse], error) {
	page, err := prtSrv.PageBusiness.GetPage(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.GetPageResponse{Data: page}), nil
}

func (prtSrv *TenancyServer) RemovePage(
	ctx context.Context,
	req *connect.Request[tenancyv1.RemovePageRequest],
) (*connect.Response[tenancyv1.RemovePageResponse], error) {
	err := prtSrv.PageBusiness.RemovePage(ctx, req.Msg)
	if err != nil {
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.RemovePageResponse{
		Succeeded: true,
	}), nil
}
