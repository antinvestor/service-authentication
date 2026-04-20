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
