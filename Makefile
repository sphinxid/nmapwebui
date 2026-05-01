.PHONY: build run worker clean test vet docker-up docker-down

# Build both binaries
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

# Docker compose up
docker-up:
	docker compose up -d --build

# Docker compose down
docker-down:
	docker compose down
