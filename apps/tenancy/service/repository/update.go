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
	"errors"
	"fmt"
	"slices"

	"github.com/pitabwire/frame/v3/data"
	"github.com/pitabwire/frame/v3/datastore"
)

// ErrUpdateConflict reports an update that matched no row: the entity's
// version no longer equals the stored one (a concurrent writer got there
// first) or the row is gone. Callers must reload and retry, never report
// success.
var ErrUpdateConflict = errors.New("update conflict: record was modified or removed concurrently")

// versionedColumns are written on every update so the optimistic lock
// actually advances. BaseRepository.Update filters on the loaded version and
// BaseModel.BeforeUpdate bumps it in memory, but a column list without these
// leaves the stored version unchanged and a stale writer would still match.
var versionedColumns = []string{"version", "modified_at"}

// UpdateVersioned writes the given columns of entity under its optimistic
// lock and fails with ErrUpdateConflict when no row matched, which
// BaseRepository.Update otherwise reports as a silent zero-row success.
func UpdateVersioned[T data.BaseModelI](
	ctx context.Context,
	repo datastore.BaseRepository[T],
	entity T,
	columns ...string,
) error {
	if len(columns) == 0 {
		return errors.New("update requires an explicit column list")
	}

	fields := slices.Clone(columns)
	for _, col := range versionedColumns {
		if !slices.Contains(fields, col) {
			fields = append(fields, col)
		}
	}

	expectedVersion := entity.GetVersion()
	rows, err := repo.Update(ctx, entity, fields...)
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: id=%s version=%d", ErrUpdateConflict, entity.GetID(), expectedVersion)
	}
	return nil
}
