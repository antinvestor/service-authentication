# Service-specific configuration
SERVICE_NAME := authentication
APP_DIRS     := apps/default apps/tenancy

# Bootstrap: download shared Makefile.common if missing
ifeq (,$(wildcard .tmp/Makefile.common))
  $(shell mkdir -p .tmp && curl -sSfL https://raw.githubusercontent.com/antinvestor/common/main/Makefile.common -o .tmp/Makefile.common)
endif

include .tmp/Makefile.common

# Migration helpers
.PHONY: new-partition new-service check-ids
new-partition: ## Scaffold a new partition seed migration
	@./tools/migrations/new-partition.sh

new-service: ## Scaffold a new service-account seed migration
	@./tools/migrations/new-service.sh

check-ids: ## Verify IDS.md registry is in sync with migration xids
	@./tools/migrations/check-ids.sh

# Run check-ids as part of the shared `format` target so CI catches drift.
format: check-ids

# Testcontainers only pulls an image when it is missing locally, so a stale
# `:latest` (e.g. service-profile) silently diverges from CI. Refresh every
# `:latest` image referenced by pkg/tests before the shared `test` target.
# Best-effort: offline runs warn and fall back to the local copy.
TEST_IMAGES := $(shell grep -hoE '"[a-z0-9./_-]+:latest"' pkg/tests/*_dep.go | tr -d '"' | sort -u)

.PHONY: pull-test-images
pull-test-images: ## Refresh the :latest images used by testcontainers
	@for img in $(TEST_IMAGES); do \
		docker pull -q $$img >/dev/null 2>&1 \
			|| echo "warn: could not pull $$img; using local copy (may be stale)"; \
	done

test: pull-test-images
