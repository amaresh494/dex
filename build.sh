go mod tidy
rm -f bin/*
make build
mv bin/dex bin/oidc
