# go settings
GOFLAGS := -mod=vendor
GO := GOFLAGS=$(GOFLAGS) GO111MODULE=on CGO_ENABLED=0 go
GOTEST := GOFLAGS=$(GOFLAGS) GO111MODULE=on CGO_ENABLED=1 go # -race needs cgo

ifndef DATE
	DATE := $(shell date -u '+%Y%m%d')
endif

ifndef SHA
	SHA := $(shell git rev-parse --short HEAD)
endif

.PHONY: lint
lint:
	golint $(shell $(GO) list ./...)

.PHONY: check-vendor
check-vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	git update-index --refresh
	git diff-index --quiet HEAD

.PHONY: test
test:
	$(GOTEST) test -coverprofile coverage.out -race -v ./...

.PHONY: build
build: cmd/authproxy-ldap

.PHONY: cmd/authproxy-ldap
cmd/authproxy-ldap:
	$(GO) build -v -o ./cmd/authproxy-ldap ./cmd

.PHONY: container-proxy
container-proxy: cmd/authproxy-ldap
	docker build -t cbrgm/authproxy-ldap:latest ./cmd

.PHONY: gencerts
gencerts:
	SAN=DNS.1:localhost ./gencerts.sh