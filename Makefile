.PHONY: build run worker clean test vet deploy restart logs down css css-watch vendor frontend

# Build both binaries locally
build:
	CGO_ENABLED=1 go build -o bin/server ./cmd/server
	CGO_ENABLED=1 go build -o bin/worker ./cmd/worker

# Run the server locally
run: build
	./bin/server

# Run the worker locally
worker: build
	./bin/worker

# Frontend assets. The outputs (static/css/app.css, static/vendor/) are
# committed, so these only need to run after changing templates or CSS,
# or when upgrading a frontend library. No Node required: Tailwind runs as
# a standalone binary downloaded into bin/.
TAILWIND_VERSION ?= 3.4.17
TAILWIND_BIN := bin/tailwindcss
UNAME_S := $(shell uname -s | tr A-Z a-z)
UNAME_M := $(shell uname -m)
TW_OS := $(if $(findstring darwin,$(UNAME_S)),macos,linux)
TW_ARCH := $(if $(filter arm64 aarch64,$(UNAME_M)),arm64,x64)

$(TAILWIND_BIN):
	@mkdir -p bin
	curl -fsSL -o $@ https://github.com/tailwindlabs/tailwindcss/releases/download/v$(TAILWIND_VERSION)/tailwindcss-$(TW_OS)-$(TW_ARCH)
	chmod +x $@

css: $(TAILWIND_BIN)
	$(TAILWIND_BIN) -i static/css/input.css -o static/css/app.css --minify

css-watch: $(TAILWIND_BIN)
	$(TAILWIND_BIN) -i static/css/input.css -o static/css/app.css --watch

vendor:
	./scripts/vendor.sh

frontend: vendor css

# Run go vet
vet:
	go vet ./...

# Run tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -rf bin/

# Deploy: rebuild images and restart (uses layer cache - fast when only code changed)
deploy:
	sudo docker compose build
	sudo docker compose up -d

# Force full rebuild (slow - only needed when Dockerfile or deps change)
deploy-full:
	sudo docker compose build --no-cache
	sudo docker compose up -d

# Restart containers without rebuilding (instant - for config/env changes only)
restart:
	sudo docker compose restart

# View logs
logs:
	sudo docker compose logs -f --tail=50

# Stop containers (preserves data volumes)
down:
	sudo docker compose down

# Stop containers AND delete data (destructive!)
down-clean:
	sudo docker compose down -v
