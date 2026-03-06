package handlers

import (
	"context"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/pitabwire/frame/security/authorizer"
	"github.com/pitabwire/util"
)

func (prtSrv *PartitionServer) CreatePage(
	ctx context.Context,
	req *connect.Request[partitionv1.CreatePageRequest],
) (*connect.Response[partitionv1.CreatePageResponse], error) {
	if err := prtSrv.authz.CanPagesManage(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	logger := util.Log(ctx)
	page, err := prtSrv.PageBusiness.CreatePage(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" CreatePage -- could not create a new page")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.CreatePageResponse{Data: page}), nil
}

func (prtSrv *PartitionServer) ListPage(
	ctx context.Context,
	req *connect.Request[partitionv1.ListPageRequest],
	stream *connect.ServerStream[partitionv1.ListPageResponse],
) error {
	if err := prtSrv.authz.CanPagesView(ctx); err != nil {
		return authorizer.ToConnectError(err)
	}
	logger := util.Log(ctx)
	pages, err := prtSrv.PageBusiness.ListPages(ctx, req.Msg.GetPartitionId())
	if err != nil {
		logger.WithError(err).Debug("ListPage -- could not list pages")
		return prtSrv.toAPIError(err)
	}
	return stream.Send(&partitionv1.ListPageResponse{Data: pages})
}

func (prtSrv *PartitionServer) UpdatePage(
	ctx context.Context,
	req *connect.Request[partitionv1.UpdatePageRequest],
) (*connect.Response[partitionv1.UpdatePageResponse], error) {
	if err := prtSrv.authz.CanPagesManage(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	logger := util.Log(ctx)
	page, err := prtSrv.PageBusiness.UpdatePage(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug("UpdatePage -- could not update page")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.UpdatePageResponse{Data: page}), nil
}

func (prtSrv *PartitionServer) GetPage(
	ctx context.Context,
	req *connect.Request[partitionv1.GetPageRequest],
) (*connect.Response[partitionv1.GetPageResponse], error) {
	if err := prtSrv.authz.CanPagesView(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	logger := util.Log(ctx)
	page, err := prtSrv.PageBusiness.GetPage(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" GetPage -- could not get page")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.GetPageResponse{Data: page}), nil
}

func (prtSrv *PartitionServer) RemovePage(
	ctx context.Context,
	req *connect.Request[partitionv1.RemovePageRequest],
) (*connect.Response[partitionv1.RemovePageResponse], error) {
	if err := prtSrv.authz.CanPagesManage(ctx); err != nil {
		return nil, authorizer.ToConnectError(err)
	}
	logger := util.Log(ctx)
	err := prtSrv.PageBusiness.RemovePage(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" RemovePage -- could not remove page")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.RemovePageResponse{
		Succeeded: true,
	}), nil
}
