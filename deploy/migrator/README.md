# Migrator build dependencies

This Go tool module builds the upstream `dbmate` executable with a checked-in
dependency graph. The upstream dbmate release can lag behind security fixes in
its Go dependencies, so updating only the dbmate version is not sufficient.

The root Dockerfile builds this module with `-mod=readonly`. Keep `go.mod` and
`go.sum` together; do not replace the build with `go install dbmate@version`,
which would bypass these dependency selections.

To update dbmate or a dependency, use the Go version from the Dockerfile:

```bash
cd deploy/migrator
go get -tool github.com/amacneil/dbmate/v2@<version>
go get <affected-module>@<patched-version>
go mod tidy
```

Then build and scan the `gateway-migrator` Docker target and verify that it can
apply the Gateway migrations to a disposable PostgreSQL database.
