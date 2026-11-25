# Copyright (c) 2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

PROJECT_ROOT = $(abspath $(dir $(firstword $(MAKEFILE_LIST))))

# renovate: datasource=github-releases depName=golangci/golangci-lint versioning=semver
GOLANGCI_LINT_VERSION="v2.15.0"

.PHONY: all
all: tidy build lint test

.PHONY: deps
deps: lint-deps go-deps

.PHONY: go-deps
go-deps:
	go mod download
	go mod verify

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: build
build:
	go build ./...

.PHONY: test
test:
	go test -race -coverprofile=$(PROJECT_ROOT)/coverage.out -covermode=atomic ./...
	cd $(PROJECT_ROOT)/e2e/yaegi && go test -race ./...

.PHONY: bench
bench:
	go test -run '^$$' -bench . -benchmem .
	cd $(PROJECT_ROOT)/e2e/yaegi && go test -run '^$$' -bench . -benchmem .

.PHONY: lint
lint:
	$(shell go env GOPATH)/bin/golangci-lint fmt ./...
	$(shell go env GOPATH)/bin/golangci-lint run --fix ./...

.PHONY: lint-deps
lint-deps:
	@echo "Installing with $(shell go env GOVERSION)"
	GOBIN=$(shell go env GOPATH)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
