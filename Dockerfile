# Build stage
FROM golang:1.22-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev libsqlite3-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o server ./cmd/server
RUN CGO_ENABLED=1 GOOS=linux go build -o worker ./cmd/worker

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends nmap ca-certificates libsqlite3-0 wkhtmltopdf tzdata && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/server /app/server
COPY --from=builder /build/worker /app/worker
COPY --from=builder /build/templates /app/templates

RUN mkdir -p /app/instance/reports

EXPOSE 8080

CMD ["/app/server"]
