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

package tests

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pitabwire/frame/v2/data"
	"github.com/pitabwire/frame/v2/frametests/definition"
	"github.com/pitabwire/frame/v2/frametests/deps/testpostgres"
	"github.com/testcontainers/testcontainers-go"
	tcPostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type tenancyPostgresDependency struct {
	*definition.DefaultImpl
	dbname string
}

func newTenancyPostgres(dbName string, containerOpts ...definition.ContainerOption) definition.TestResource {
	opts := definition.ContainerOpts{
		ImageName:      testpostgres.PostgresqlDBImage,
		UserName:       testpostgres.DBUser,
		Credential:     testpostgres.DBPassword,
		Ports:          []string{"5432/tcp"},
		NetworkAliases: []string{"postgres", "db-postgres"},
	}
	opts.Setup(containerOpts...)

	return &tenancyPostgresDependency{
		DefaultImpl: definition.NewDefaultImpl(opts, ""),
		dbname:      dbName,
	}
}

func (d *tenancyPostgresDependency) Setup(ctx context.Context, ntwk *testcontainers.DockerNetwork) error {
	containerCustomize := d.ConfigurationExtend(ctx, ntwk, []testcontainers.ContainerCustomizer{
		tcPostgres.WithDatabase(d.dbname),
		tcPostgres.WithUsername(d.Opts().UserName),
		tcPostgres.WithPassword(d.Opts().Credential),
		testcontainers.WithCmdArgs("-c", "max_connections=300"),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForListeningPort("5432/tcp"),
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(testpostgres.OccurrenceValue).
					WithStartupTimeout(testpostgres.TimeoutInSeconds*time.Second),
			),
		),
	}...)

	pgContainer, err := tcPostgres.Run(ctx, d.Name(), containerCustomize...)
	if err != nil {
		return fmt.Errorf("failed to start postgres container: %w", err)
	}

	d.SetContainer(pgContainer)
	if err = waitForPostgresReady(ctx, d.GetDS(ctx)); err != nil {
		_ = pgContainer.Terminate(ctx)
		return fmt.Errorf("wait for postgres readiness: %w", err)
	}

	return nil
}

func (d *tenancyPostgresDependency) GetDS(ctx context.Context) data.DSN {
	ds := d.DefaultImpl.GetDS(ctx)
	return data.DSN(
		fmt.Sprintf("postgres://%s:%s@%s/%s", d.Opts().UserName, d.Opts().Credential, ds.String(), d.dbname),
	)
}

func (d *tenancyPostgresDependency) GetInternalDS(ctx context.Context) data.DSN {
	ds := d.DefaultImpl.GetInternalDS(ctx)
	return data.DSN(
		fmt.Sprintf("postgres://%s:%s@%s/%s", d.Opts().UserName, d.Opts().Credential, ds.String(), d.dbname),
	)
}

func (d *tenancyPostgresDependency) GetRandomisedDS(
	ctx context.Context,
	randomisedPrefix string,
) (data.DSN, func(context.Context), error) {
	return testpostgres.CreateDatabase(ctx, d.GetDS(ctx), randomisedPrefix)
}

func waitForPostgresReady(ctx context.Context, dsn data.DSN) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for {
		cfg, err := pgxpool.ParseConfig(dsn.String())
		if err == nil {
			cfg.MaxConns = 1
			pool, poolErr := pgxpool.NewWithConfig(deadlineCtx, cfg)
			if poolErr == nil {
				err = pool.Ping(deadlineCtx)
				pool.Close()
				if err == nil {
					return nil
				}
			} else {
				err = poolErr
			}
		}

		if deadlineCtx.Err() != nil {
			return err
		}

		select {
		case <-time.After(250 * time.Millisecond):
		case <-deadlineCtx.Done():
			return err
		}
	}
}
