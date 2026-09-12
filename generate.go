package main

//go:generate bash -c "mkdir -p codegen && go tool oapi-codegen -generate types,server,spec -package codegen api/casaos/openapi.yaml > codegen/casaos_api.go"
//go:generate bash -c "mkdir -p codegen/message_bus && go tool oapi-codegen -generate types,client -package message_bus https://raw.githubusercontent.com/IceWhaleTech/CasaOS-MessageBus/ba87168fcfa4ac5ff7a114f66a139eb5fe427646/api/message_bus/openapi.yaml > codegen/message_bus/api.go"
