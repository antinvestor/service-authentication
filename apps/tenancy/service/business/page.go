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

package business

import (
	"context"

	tenancyv1 "buf.build/gen/go/antinvestor/tenancy/protocolbuffers/go/tenancy/v1"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/antinvestor/service-authentication/apps/tenancy/service/repository"
	"github.com/pitabwire/frame/v2"
	"github.com/pitabwire/frame/v2/data"
)

type PageBusiness interface {
	GetPage(ctx context.Context, request *tenancyv1.GetPageRequest) (*tenancyv1.PageObject, error)
	ListPages(ctx context.Context, partitionID string) ([]*tenancyv1.PageObject, error)
	UpdatePage(ctx context.Context, request *tenancyv1.UpdatePageRequest) (*tenancyv1.PageObject, error)
	RemovePage(ctx context.Context, request *tenancyv1.RemovePageRequest) error
	CreatePage(ctx context.Context, request *tenancyv1.CreatePageRequest) (*tenancyv1.PageObject, error)
}

func NewPageBusiness(
	service *frame.Service,
	pageRepo repository.PageRepository,
	partitionRepo repository.PartitionRepository,
) PageBusiness {
	return &pageBusiness{
		service:       service,
		pageRepo:      pageRepo,
		partitionRepo: partitionRepo,
	}
}

type pageBusiness struct {
	service       *frame.Service
	pageRepo      repository.PageRepository
	partitionRepo repository.PartitionRepository
}

func (ab *pageBusiness) GetPage(
	ctx context.Context,
	request *tenancyv1.GetPageRequest,
) (*tenancyv1.PageObject, error) {
	page, err := ab.pageRepo.GetByPartitionAndName(ctx, request.GetPartitionId(), request.GetName())
	if err != nil {
		return nil, err
	}

	return page.ToAPI(), nil
}

func (ab *pageBusiness) ListPages(ctx context.Context, partitionID string) ([]*tenancyv1.PageObject, error) {
	pages, err := ab.pageRepo.ListByPartition(ctx, partitionID)
	if err != nil {
		return nil, err
	}

	result := make([]*tenancyv1.PageObject, 0, len(pages))
	for _, p := range pages {
		result = append(result, p.ToAPI())
	}
	return result, nil
}

func (ab *pageBusiness) UpdatePage(ctx context.Context, request *tenancyv1.UpdatePageRequest) (*tenancyv1.PageObject, error) {
	page, err := ab.pageRepo.GetByID(ctx, request.GetId())
	if err != nil {
		return nil, err
	}

	if request.GetName() != "" {
		page.Name = request.GetName()
	}
	if request.GetHtml() != "" {
		page.HTML = request.GetHtml()
	}
	if request.GetState() != 0 {
		page.State = int32(request.GetState())
	}
	if request.GetProperties() != nil {
		page.Properties = request.GetProperties().AsMap()
	}

	_, err = ab.pageRepo.Update(ctx, page, "name", "html", "state", "properties")
	if err != nil {
		return nil, err
	}

	return page.ToAPI(), nil
}

func (ab *pageBusiness) RemovePage(ctx context.Context, request *tenancyv1.RemovePageRequest) error {
	return ab.pageRepo.Delete(ctx, request.GetId())
}

func (ab *pageBusiness) CreatePage(
	ctx context.Context,
	request *tenancyv1.CreatePageRequest,
) (*tenancyv1.PageObject, error) {
	partition, err := ab.partitionRepo.GetByID(ctx, request.GetPartitionId())
	if err != nil {
		return nil, err
	}

	page := &models.Page{
		Name: request.GetName(),
		HTML: request.GetHtml(),
		BaseModel: data.BaseModel{
			TenantID:    partition.TenantID,
			PartitionID: partition.GetID(),
		},
	}

	err = ab.pageRepo.Create(ctx, page)
	if err != nil {
		return nil, err
	}

	return page.ToAPI(), nil
}
