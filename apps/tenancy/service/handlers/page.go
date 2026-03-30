package handlers

import (
	"context"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"connectrpc.com/connect"
	"github.com/pitabwire/util"
)

func (prtSrv *TenancyServer) CreatePage(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreatePageRequest],
) (*connect.Response[tenancyv1.CreatePageResponse], error) {
	logger := util.Log(ctx)
	page, err := prtSrv.PageBusiness.CreatePage(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" CreatePage -- could not create a new page")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.CreatePageResponse{Data: page}), nil
}

func (prtSrv *TenancyServer) ListPage(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListPageRequest],
	stream *connect.ServerStream[tenancyv1.ListPageResponse],
) error {
	logger := util.Log(ctx)
	pages, err := prtSrv.PageBusiness.ListPages(ctx, req.Msg.GetPartitionId())
	if err != nil {
		logger.WithError(err).Debug("ListPage -- could not list pages")
		return prtSrv.toAPIError(err)
	}
	return stream.Send(&tenancyv1.ListPageResponse{Data: pages})
}

func (prtSrv *TenancyServer) UpdatePage(
	ctx context.Context,
	req *connect.Request[tenancyv1.UpdatePageRequest],
) (*connect.Response[tenancyv1.UpdatePageResponse], error) {
	logger := util.Log(ctx)
	page, err := prtSrv.PageBusiness.UpdatePage(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug("UpdatePage -- could not update page")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.UpdatePageResponse{Data: page}), nil
}

func (prtSrv *TenancyServer) GetPage(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetPageRequest],
) (*connect.Response[tenancyv1.GetPageResponse], error) {
	logger := util.Log(ctx)
	page, err := prtSrv.PageBusiness.GetPage(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" GetPage -- could not get page")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.GetPageResponse{Data: page}), nil
}

func (prtSrv *TenancyServer) RemovePage(
	ctx context.Context,
	req *connect.Request[tenancyv1.RemovePageRequest],
) (*connect.Response[tenancyv1.RemovePageResponse], error) {
	logger := util.Log(ctx)
	err := prtSrv.PageBusiness.RemovePage(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" RemovePage -- could not remove page")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&tenancyv1.RemovePageResponse{
		Succeeded: true,
	}), nil
}
