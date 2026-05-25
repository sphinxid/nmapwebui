#!/bin/bash

# Performance monitoring script for NmapWebUI development
# Shows real-time resource usage of the development environment

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}=== NmapWebUI Performance Monitor ===${NC}"
}

monitor_performance() {
    while true; do
        clear
        print_header
        echo "$(date)"
        echo ""
        
        # System info
        echo -e "${GREEN}System Information:${NC}"
        echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
        echo "Memory Usage: $(free -h | awk 'NR==2{printf "%.1f%% (%s/%s)\n", $3*100/$2, $3, $2}')"
        echo ""
        
        # Redis
        if pgrep -x "redis-server" > /dev/null; then
            REDIS_PID=$(pgrep -x "redis-server")
            REDIS_MEM=$(ps -p $REDIS_PID -o %mem,rss --no-headers | awk '{print $1"% ("$2" KB)"}')
            echo -e "${GREEN}Redis (PID: $REDIS_PID):${NC} $REDIS_MEM"
        else
            echo -e "${YELLOW}Redis:${NC} Not running"
        fi
        echo ""
        
        # Server
        if pgrep -f "./bin/server" > /dev/null; then
            SERVER_PID=$(pgrep -f "./bin/server")
            SERVER_MEM=$(ps -p $SERVER_PID -o %mem,rss --no-headers | awk '{print $1"% ("$2" KB)"}')
            SERVER_CPU=$(ps -p $SERVER_PID -o %cpu --no-headers | awk '{print $1"%"}')
            echo -e "${GREEN}Server (PID: $SERVER_PID):${NC} CPU: $SERVER_CPU, Memory: $SERVER_MEM"
        else
            echo -e "${YELLOW}Server:${NC} Not running"
        fi
        echo ""
        
        # Worker
        if pgrep -f "./bin/worker" > /dev/null; then
            WORKER_PID=$(pgrep -f "./bin/worker" | head -1)
            WORKER_MEM=$(ps -p $WORKER_PID -o %mem,rss --no-headers | awk '{print $1"% ("$2" KB)"}')
            WORKER_CPU=$(ps -p $WORKER_PID -o %cpu --no-headers | awk '{print $1"%"}')
            echo -e "${GREEN}Worker (PID: $WORKER_PID):${NC} CPU: $WORKER_CPU, Memory: $WORKER_MEM"
        else
            echo -e "${YELLOW}Worker:${NC} Not running"
        fi
        echo ""
        
        # Database size
        if [ -f "./instance/app.db" ]; then
            DB_SIZE=$(du -sh ./instance/app.db | awk '{print $1}')
            echo -e "${GREEN}Database Size:${NC} $DB_SIZE"
        fi
        
        # Binary sizes
        if [ -f "./bin/server" ] && [ -f "./bin/worker" ]; then
            SERVER_SIZE=$(ls -lh ./bin/server | awk '{print $5}')
            WORKER_SIZE=$(ls -lh ./bin/worker | awk '{print $5}')
            echo -e "${GREEN}Binary Sizes:${NC} Server: $SERVER_SIZE, Worker: $WORKER_SIZE"
        fi
        
        echo ""
        echo -e "${BLUE}Press Ctrl+C to exit${NC}"
        sleep 3
    done
}

case "$1" in
    "monitor")
        monitor_performance
        ;;
    *)
        echo "Usage: $0 monitor"
        echo "Shows real-time performance monitoring for NmapWebUI"
        exit 1
        ;;
esac