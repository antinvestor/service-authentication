package handlers

import (
	"context"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/business"

	partitionv1 "github.com/antinvestor/apis/go/partition/v1"
)

func (prtSrv *PartitionServer) CreatePage(
	ctx context.Context,
	req *partitionv1.CreatePageRequest,
) (*partitionv1.CreatePageResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	pageBusiness := business.NewPageBusiness(ctx, prtSrv.Service)
	page, err := pageBusiness.CreatePage(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" CreatePage -- could not create a new page")
		return nil, prtSrv.toAPIError(err)
	}
	return &partitionv1.CreatePageResponse{Data: page}, nil
}

func (prtSrv *PartitionServer) GetPage(
	ctx context.Context,
	req *partitionv1.GetPageRequest,
) (*partitionv1.GetPageResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	pageBusiness := business.NewPageBusiness(ctx, prtSrv.Service)
	page, err := pageBusiness.GetPage(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" GetPage -- could not get page")
		return nil, prtSrv.toAPIError(err)
	}
	return &partitionv1.GetPageResponse{Data: page}, nil
}

func (prtSrv *PartitionServer) RemovePage(
	ctx context.Context,
	req *partitionv1.RemovePageRequest,
) (*partitionv1.RemovePageResponse, error) {
	logger := prtSrv.Service.Log(ctx)
	pageBusiness := business.NewPageBusiness(ctx, prtSrv.Service)
	err := pageBusiness.RemovePage(ctx, req)
	if err != nil {
		logger.WithError(err).Debug(" RemovePage -- could not remove page")
		return &partitionv1.RemovePageResponse{
			Succeeded: false,
		}, prtSrv.toAPIError(err)
	}
	return &partitionv1.RemovePageResponse{
		Succeeded: true,
	}, nil
}
