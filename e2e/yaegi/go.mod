module github.com/hemilabs/traefik-jsonrpc-filter/e2e/yaegi

go 1.25

toolchain go1.26.11

require (
	github.com/hemilabs/traefik-jsonrpc-filter v0.0.0
	github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c
	github.com/traefik/yaegi v0.16.3
)

replace github.com/hemilabs/traefik-jsonrpc-filter => ../..
