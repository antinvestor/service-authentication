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

package repository

import (
	"context"

	"github.com/antinvestor/service-authentication/apps/tenancy/service/models"
	"github.com/pitabwire/frame/v2/datastore"
	"github.com/pitabwire/frame/v2/datastore/pool"
	"github.com/pitabwire/frame/v2/security"
	"github.com/pitabwire/frame/v2/workerpool"
)

// ServiceNamespaceRepository manages registered service namespace records.
type ServiceNamespaceRepository interface {
	datastore.BaseRepository[*models.ServiceNamespace]
	GetByNamespace(ctx context.Context, namespace string) (*models.ServiceNamespace, error)
	ListAll(ctx context.Context) ([]*models.ServiceNamespace, error)
}

type serviceNamespaceRepository struct {
	datastore.BaseRepository[*models.ServiceNamespace]
}

func NewServiceNamespaceRepository(ctx context.Context, dbPool pool.Pool, workMan workerpool.Manager) ServiceNamespaceRepository {
	return &serviceNamespaceRepository{
		BaseRepository: datastore.NewBaseRepository[*models.ServiceNamespace](
			ctx, dbPool, workMan, func() *models.ServiceNamespace { return &models.ServiceNamespace{} },
		),
	}
}

func (r *serviceNamespaceRepository) GetByNamespace(ctx context.Context, namespace string) (*models.ServiceNamespace, error) {
	// Service namespaces are global — skip tenant scoping.
	ctx = security.SkipTenancyChecksOnClaims(ctx)
	ns := &models.ServiceNamespace{}
	err := r.Pool().DB(ctx, true).First(ns, "namespace = ?", namespace).Error
	if err != nil {
		return nil, err
	}
	return ns, nil
}

func (r *serviceNamespaceRepository) ListAll(ctx context.Context) ([]*models.ServiceNamespace, error) {
	// Service namespaces are global — skip tenant scoping.
	ctx = security.SkipTenancyChecksOnClaims(ctx)
	var namespaces []*models.ServiceNamespace
	err := r.Pool().DB(ctx, true).Order("namespace").Find(&namespaces).Error
	if err != nil {
		return nil, err
	}
	return namespaces, nil
}
