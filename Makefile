.PHONY: api build-all build-bastion build-client build-server

build-all: build-bastion build-client build-server

build-bastion: api
	go build -o bin/ssh-ca.bastion ./cmd/bastion

build-client:
	go build -o bin/ssh-ca.client ./cmd/client

build-server: api
	go build -o bin/ssh-ca.server ./cmd/server

api:
	protoc --go_out=api/server --go-grpc_out=api/server api/server/api.proto
