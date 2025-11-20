GOCACHE ?= $(CURDIR)/.gocache
GOMODCACHE ?= $(CURDIR)/.gomodcache
GOBIN ?= $(shell go env GOPATH)/bin

ifneq (,$(wildcard .env))
SQLITE_DSN ?= $(shell sed -n 's/^SQLITE_DSN=//p' .env)
CHAIN_RPC_URL ?= $(shell sed -n 's/^CHAIN_RPC_URL=//p' .env)
USD_PER_MAX_OP_DEFAULT ?= $(shell sed -n 's/^USD_PER_MAX_OP_DEFAULT=//p' .env)
endif

DB_FILE := $(or $(SQLITE_DSN),./data/app.db)

tools:
	@echo "Installing tools..."
	@go install github.com/air-verse/air@latest
	@go install github.com/swaggo/swag/cmd/swag@latest

run:
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run ./cmd/server

dev: tools
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GOBIN)/air -c .air.toml

tidy:
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go mod tidy

swagger:
	@$(GOBIN)/swag init --generalInfo cmd/server/main.go --output docs --parseInternal --parseDependency
	@echo "Swagger docs generated under docs/"

build:
	@mkdir -p bin
	@GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build -o bin/server ./cmd/server

.PHONY: clean-db
clean-db:
	@if [ -n "$(DB_FILE)" ] && [ -f "$(DB_FILE)" ]; then \
		echo "Removing $$PWD/$(DB_FILE)"; \
		rm -f "$(DB_FILE)"; \
	else \
		echo "DB file not found at $(DB_FILE) (set SQLITE_DSN or ensure file exists)"; \
	fi
	@dir_path=$$(dirname "$(DB_FILE)"); \
	if [ $$dir_path != "." ] && [ -d "$$dir_path" ]; then \
		echo "Cleaning SQLite journal files in $$dir_path"; \
		find "$$dir_path" -maxdepth 1 -type f \( -name '*.db-journal' -o -name '*.sqlite-journal' \) -delete; \
	fi
