GOCMD=go
BIN_DIR:=bin

.PHONY: pre clean build format help
.DEFAULT_GOAL := help

pre: ## Create the bin directory
	mkdir -p $(BIN_DIR)

clean: ## Clean the bin directory
	rm -rf $(BIN_DIR)

build: pre ## Create the main binary
	GO111MODULE=on CGO_ENABLED=0 $(GOCMD) build -ldflags="-s -w" -o bin/heybabe *.go

format: ## Format the source code
	find . -name '*.go' -not -path './vendor/*' | xargs -n1 go fmt

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'