GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get


# # Binary names
DIR_NAME=go-php/
BINARY_NAME=php_pgp
SHARE_MODULE_NAME=./lib.so

build: 
	$(GOBUILD)   -o $(SHARE_MODULE_NAME)  -buildmode c-shared  -v  ./ffi.go
