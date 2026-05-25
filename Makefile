.PHONY: build run worker clean test vet deploy restart logs down

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
