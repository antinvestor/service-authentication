package handlers

import (
	"context"

	partitionv1 "buf.build/gen/go/antinvestor/partition/protocolbuffers/go/partition/v1"
	"connectrpc.com/connect"
	"github.com/pitabwire/util"
)

func (prtSrv *PartitionServer) CreatePage(
	ctx context.Context,
	req *connect.Request[partitionv1.CreatePageRequest],
) (*connect.Response[partitionv1.CreatePageResponse], error) {
	logger := util.Log(ctx)
	page, err := prtSrv.PageBusiness.CreatePage(ctx, req.Msg)
	if err != nil {
		logger.WithError(err).Debug(" CreatePage -- could not create a new page")
		return nil, prtSrv.toAPIError(err)
	}
	return connect.NewResponse(&partitionv1.CreatePageResponse{Data: page}), nil
}

func (prtSrv *PartitionServer) GetPage(
	ctx context.Context,
	req *connect.Request[partitionv1.GetPageRequest],
) (*connect.Response[partitionv1.GetPageResponse], error) {
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
