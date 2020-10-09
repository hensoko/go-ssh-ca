.PHONY: api

api:
	protoc -I api/ --go-grpc_out=api api/api.proto
