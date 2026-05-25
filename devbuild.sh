#!/bin/bash

# NmapWebUI Local Development Script
# This script helps manage the local development environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=================================${NC}"
    echo -e "${BLUE}  NmapWebUI Dev Environment${NC}"
    echo -e "${BLUE}=================================${NC}"
}

# Function to check if Redis is running
check_redis() {
    if pgrep -x "redis-server" > /dev/null; then
        print_status "Redis is running"
        return 0
    else
        print_warning "Redis is not running"
        return 1
    fi
}

# Function to stop all processes
stop_all() {
    print_status "Stopping all NmapWebUI processes..."
    pkill -f "./bin/server" || true
    pkill -f "./bin/worker" || true
    print_status "All processes stopped"
}

# Function to start development environment
start_dev() {
    print_header
    
    # Check Redis
    if ! check_redis; then
        print_error "Please start Redis first: redis-server"
        exit 1
    fi
    
    # Build binaries
    print_status "Building binaries..."
    go build -o bin/server cmd/server/main.go
    go build -o bin/worker cmd/worker/main.go
    
    # Set environment variables
    export SUPERADMIN_USERNAME=firman
    export SUPERADMIN_PASSWORD=Ajkshkl12j3kljakdslfj21
    export SUPERADMIN_EMAIL=firman@kodelatte.com
    export DATABASE_URL=./instance/app.db
    export REDIS_URL=redis://localhost:6379/0
    export NMAP_REPORTS_DIR=./instance/reports
    export DEBUG=true
    
    # Start server
    print_status "Starting server..."
    ./bin/server &
    SERVER_PID=$!
    
    # Start worker
    print_status "Starting worker..."
    ./bin/worker &
    WORKER_PID=$!
    
    # Wait a moment for processes to start
    sleep 3
    
    # Check if processes are running
    if kill -0 $SERVER_PID 2>/dev/null; then
        print_status "Server started successfully (PID: $SERVER_PID)"
    else
        print_error "Server failed to start"
        exit 1
    fi
    
    if kill -0 $WORKER_PID 2>/dev/null; then
        print_status "Worker started successfully (PID: $WORKER_PID)"
    else
        print_error "Worker failed to start"
        exit 1
    fi
    
    print_header
    print_status "Development environment is ready!"
    echo -e "${GREEN}Server:${NC} http://localhost:8080"
    echo -e "${GREEN}Login:${NC} firman / Ajkshkl12j3kljakdslfj21"
    echo -e "${GREEN}Server PID:${NC} $SERVER_PID"
    echo -e "${GREEN}Worker PID:${NC} $WORKER_PID"
    print_header
    
    # Save PIDs to file for easy stopping
    echo "$SERVER_PID" > .server.pid
    echo "$WORKER_PID" > .worker.pid
}

# Function to show status
show_status() {
    print_header
    
    if check_redis; then
        REDIS_PID=$(pgrep -x "redis-server")
        echo -e "${GREEN}Redis:${NC} Running (PID: $REDIS_PID)"
    else
        echo -e "${RED}Redis:${NC} Not running"
    fi
    
    if pgrep -f "./bin/server" > /dev/null; then
        SERVER_PID=$(pgrep -f "./bin/server")
        echo -e "${GREEN}Server:${NC} Running (PID: $SERVER_PID)"
    else
        echo -e "${RED}Server:${NC} Not running"
    fi
    
    if pgrep -f "./bin/worker" > /dev/null; then
        WORKER_PID=$(pgrep -f "./bin/worker")
        echo -e "${GREEN}Worker:${NC} Running (PID: $WORKER_PID)"
    else
        echo -e "${RED}Worker:${NC} Not running"
    fi
    
    print_header
}

# Function to rebuild and restart
restart() {
    print_status "Rebuilding and restarting..."
    stop_all
    sleep 2
    start_dev
}

# Main script logic
case "$1" in
    "start")
        start_dev
        ;;
    "stop")
        stop_all
        rm -f .server.pid .worker.pid
        ;;
    "restart")
        restart
        ;;
    "status")
        show_status
        ;;
    "build")
        print_status "Building binaries..."
        go build -o bin/server cmd/server/main.go
        go build -o bin/worker cmd/worker/main.go
        print_status "Build complete"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|build}"
        echo ""
        echo "Commands:"
        echo "  start   - Start development environment"
        echo "  stop    - Stop all processes"
        echo "  restart - Rebuild and restart"
        echo "  status  - Show current status"
        echo "  build   - Build binaries only"
        exit 1
        ;;
esac