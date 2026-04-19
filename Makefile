DIST_DIR := dist
LAMBDA_BOOTSTRAP := $(DIST_DIR)/bootstrap
LAMBDA_ZIP := $(DIST_DIR)/bootstrap.zip

.PHONY: build-lambda clean test

build-lambda: $(LAMBDA_ZIP)

$(LAMBDA_ZIP): $(LAMBDA_BOOTSTRAP)
	cd $(DIST_DIR) && zip -q bootstrap.zip bootstrap

$(LAMBDA_BOOTSTRAP): $(shell find cmd internal -name '*.go') go.mod go.sum
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(LAMBDA_BOOTSTRAP) ./cmd/lambda

test:
	go test ./...

clean:
	rm -rf $(DIST_DIR)
