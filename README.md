# NmapWebUI

A modern web-based frontend for Nmap built with **Go**, **Gin**, **GORM**, **Redis**, and **robfig/cron**.

## Architecture Overview

| Layer | Technology |
|-------|------------|
| Web Framework | Gin |
| Task Queue | Redis (BRPOP) |
| Scheduler | robfig/cron |
| Database | SQLite via GORM |
| Auth | JWT + bcrypt |
| Frontend | Go html/template + Tailwind CSS |
| Live Updates | Server-Sent Events (SSE) via Redis pub/sub |
| Nmap Execution | os/exec subprocess |

## Project Structure

```
nmapwebui/
├── cmd/
│   ├── server/main.go      # HTTP server entrypoint
│   └── worker/main.go      # Background worker entrypoint
├── internal/
│   ├── config/             # Configuration (env vars)
│   ├── db/                 # GORM database init + migrations
│   ├── models/             # GORM models
│   ├── middleware/         # JWT auth middleware
│   ├── handlers/           # HTTP handlers (auth, targets, scans, reports, admin, SSE)
│   ├── services/           # Business logic (nmap, locking, reports)
│   └── scheduler/          # Cron-based schedule checker
├── templates/              # Go html/template + Tailwind frontend
├── Dockerfile              # Multi-stage build
├── docker-compose.yml      # Server + Worker + Redis
├── Makefile                # Build/run shortcuts
└── go.mod
```

## Quick Start

### Prerequisites

- Go 1.22+
- Redis
- Nmap installed on the system
- GCC (for SQLite CGO)

### Local Development

```bash
# 1. Copy environment config
cp .env.example .env

# 2. Start Redis
redis-server

# 3. Build and run the server
make run

# 4. In another terminal, start the worker
make worker
```

The server starts at http://localhost:8080. Log in with the superadmin credentials from `.env`.

### Docker Compose

```bash
# Starts Redis, Web Server, and Worker
make deploy

# View logs
make logs
```

Access at http://localhost:8080.

### Makefile Commands

| Command | Description |
|---------|-------------|
| `make deploy` | Build with layer cache and restart (fast for code-only changes) |
| `make deploy-full` | Full rebuild without cache (needed when Dockerfile changes) |
| `make restart` | Restart containers without rebuilding |
| `make logs` | Tail container logs |
| `make down` | Stop containers, **preserves database and reports** |
| `make down-clean` | Stop containers **and delete all data** (volumes removed) |

### Data Persistence

The database (`app.db`) and scan reports are stored in a Docker volume (`app_data`).
This data persists across `make deploy`, `make down`, and container restarts.

**To preserve data**: always use `make down` (runs `docker-compose down`).
**To reset everything**: use `make down-clean` (runs `docker-compose down -v`).

## Key Features

### Scan Profiles
Built-in profiles: `quick_scan`, `intense_scan`, `ping_scan`, `service_scan`, `os_detection`, `comprehensive`, plus custom argument support.

### Scheduler (robfig/cron + Redis Locks)
- Supports **daily**, **weekly**, **monthly**, and **interval** schedules
- Exactly-once execution via **Redis distributed locks**
- Schedule checker runs every 60 seconds
- Window-based deduplication prevents duplicate triggers

### Concurrency Control / Duplicate Prevention
Two layers of locking prevent race conditions:
1. **Redis lock** (`nmapwebui:lock:task:{task_id}`) — ensures only one worker runs a given task at a time
2. **DB state check** — `queued`/`running` scan runs block new ad-hoc runs

### Live Updates (SSE)
Connect to `/api/sse/scans/:run_id/events` for real-time progress:
- `progress` events from nmap `--stats-every` parsing
- `status` events (starting, running, completed, failed)
- Heartbeat keepalive for connection stability

### Report Management
Nmap outputs saved as:
- **XML** (`-oX`) — parsed into structured Host/Port findings
- **Normal text** (`-oN`) — raw output for download

### Authentication
- JWT access tokens (cookie + Bearer header)
- Role-based access (`user` / `admin`)
- Password hashing with bcrypt

## API Endpoints

| Prefix | Description |
|--------|-------------|
| `/api/auth` | Login, register, logout |
| `/api/targets` | CRUD for target groups & hosts |
| `/api/scans` | Scan tasks & runs (profiles, triggers) |
| `/api/schedules` | Enable/disable scheduled scanning |
| `/api/reports` | View reports, download XML/TXT |
| `/api/admin` | Admin stats & user listing |
| `/api/sse` | Server-Sent Events for live scan progress |

## Configuration

Set via `.env` file or environment variables:

```env
SECRET_KEY=change-me-in-production
DATABASE_URL=instance/app.db
REDIS_URL=redis://localhost:6379/0
NMAP_REPORTS_DIR=instance/reports
DEBUG=false
ACCESS_TOKEN_EXPIRE_MINUTES=120
NMAP_WORKER_POOL_SIZE=2
```

## Security Notes

- Nmap arguments are passed as a list to `exec.Command` to avoid shell injection
- Custom arguments should still be validated at the UI layer
- Passwordless sudo may be required for privileged scans (`-O`, `-sS`, etc.)
- The Docker containers use `NET_RAW` and `NET_ADMIN` capabilities for raw packet scans

## License

MIT
