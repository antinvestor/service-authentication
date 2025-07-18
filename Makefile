ENV_LOCAL_TEST=\
  TEST_DATABASE_URL=postgres://ant:secret@localhost:5436/service_authentication?sslmode=disable \
  POSTGRES_PASSWORD=secret \
  POSTGRES_DB=service_authentication \
  POSTGRES_HOST=authentication_db \
  POSTGRES_USER=ant

SERVICE		?= $(shell basename `go list`)
VERSION		?= $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || cat $(PWD)/.version 2> /dev/null || echo v0)
PACKAGE		?= $(shell go list)
PACKAGES	?= $(shell go list ./...)
FILES		?= $(shell find . -type f -name '*.go' -not -path "./vendor/*")



default: help

help:   ## show this help
	@echo 'usage: make [target] ...'
	@echo ''
	@echo 'targets:'
	@egrep '^(.+)\:\ .*##\ (.+)' ${MAKEFILE_LIST} | sed 's/:.*##/#/' | column -t -c 2 -s '#'

format:
	find . -name '*.go' -not -path './.git/*' -exec sed -i '/^import (/,/^)/{/^$$/d}' {} +
	find . -name '*.go' -not -path './.git/*' -exec goimports -w {} +
	golangci-lint run --fix

clean:  ## go clean
	go clean

fmt:    ## format the go source files
	go fmt ./...

vet:    ## run go vet on the source files
	go vet ./...

doc:    ## generate godocs and start a local documentation webserver on port 8085
	godoc -http=:8085 -index

# this command will start docker components that we set in docker-compose.yml
docker-setup: ## sets up docker container images
	docker-compose up -d --remove-orphans

# shutting down docker components
docker-stop: ## stops all docker containers
	docker-compose down

# this command will run all tests in the repo
# INTEGRATION_TEST_SUITE_PATH is used to run specific tests in Golang,
# if it's not specified it will run all tests
tests: ## runs all system tests
	go test ./... -v
	RETURNCODE=$$?; \
	if [ "$$RETURNCODE" != "0" ]; then \
		echo "unit tests failed" && exit 1; \
	fi;

build: clean fmt vet tests ## run all preliminary steps and tests the setup
