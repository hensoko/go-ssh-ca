.PHONY: api

api:
	protoc --go_out=bastion/api --go-grpc_out=bastion/api bastion/api/api.proto
