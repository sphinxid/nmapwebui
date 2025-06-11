# NmapWebUI

A web-based application that serves as a user-friendly wrapper for the Nmap network scanner. This application allows authenticated users to manage targets, define and execute Nmap scans, view scan reports, and schedule recurring scans through an intuitive web interface.

## Features

- **User Authentication & Authorization** - secure login system with role-based access
- **User Management** - admin interface for managing user accounts
- **Target Group Management** - organize and manage scan targets efficiently
- **Scan Task Creation & Configuration** - flexible scan configuration with custom Nmap options
- **Asynchronous Background Scanning** - non-blocking scan execution using a built-in scheduler
- **Task Listing & Management** - monitor and control running and queued scans
- **Scan Report Display** - comprehensive visualization of scan results
- **Multiple Scan Runs & Report History** - track scan history and compare results over time
- **Scheduled Scanning** - automated recurring scans with configurable intervals

## Prerequisites

- Python 3.8 or higher
- Nmap installed on the system
- (Optional) Gunicorn or uWSGI for production deployment
- (Optional) The User running the application should have sudo access without a password for Nmap commands requiring root privileges

## Manual Installation & Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd nmapwebui
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
apt-get install -y --no-install-recommends nmap libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libpangocairo-1.0-0
```

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

```bash
cp .env.example .env
```

Edit the `.env` file with your configuration:

```bash
# Flask configuration
FLASK_APP=run_app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key

# Database configuration (use absolute path)
DATABASE_URL=sqlite:////home/user/nmapwebui/instance/app.db

# Worker configuration
NMAP_WORKER_POOL_SIZE=4

# Nmap configuration
NMAP_REPORTS_DIR=/home/user/nmapwebui/instance/reports

# Server configuration
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
```

### 5. Initialize Database

```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

### 6. Create Admin User

```bash
python create_admin.py
```

## Running the Application Manually

The application now runs as a single process, managing the web server, background workers, and scheduler internally.

### 1. Start Flask Application

```bash
python run_app.py
```

The application will be accessible at `http://127.0.0.1:5000` (or the URL shown in the console).

## Docker Deployment

The application includes Docker support with automated service management using Supervisor.

### Prerequisites

- Docker installed on your system
- Docker Compose (usually included with Docker Desktop)

### Configuration for Docker

Create and configure your `.env` file (you can copy from `.env.docker.example`):

```bash
cp .env.docker.example .env
```

**Important Docker-specific configuration:**

```bash
# Database - path inside a container with a volume mount
DATABASE_URL=sqlite:////app/instance/app.db

# Worker configuration
NMAP_WORKER_POOL_SIZE=4

# Reports directory - mounted volume path
NMAP_REPORTS_DIR=/app/instance/reports

# Optional: Auto-create admin user on first run (password minimum 8 characters)
ADMIN_USER=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=your-secure-password-min-8-chars

# Other required variables
SECRET_KEY=your-secret-key
FLASK_HOST=0.0.0.0
FLASK_PORT=51234
```

### Building and Running with Docker

#### Option 1: Using Docker Compose (Recommended)

```bash
docker compose up -d
```

This will:
- Build the application image
- Start the NmapWebUI application with all services managed by Supervisor
- Expose the application on `http://localhost:51234`

#### Option 2: Manual Docker Build and Run

Build the image:

```bash
docker build -t nmapwebui .
```

Run the container:

```bash
docker run -d \
  --name nmapwebui-container \
  -p 51234:51234 \
  --env-file .env \
  nmapwebui
```

### Managing the Docker Container

#### View logs:

```bash
# All logs
docker logs nmapwebui-container

# Follow logs in real-time
docker logs -f nmapwebui-container

# Using Docker Compose
docker compose logs -f
```

#### Stop the application:

```bash
# Docker Compose
docker compose down

# Manual container
docker stop nmapwebui-container
```

#### Restart services:

```bash
# Docker Compose
docker compose restart

# Manual container
docker restart nmapwebui-container
```

## Usage

1. **Access the web interface** at the configured URL
2. **Log in** with your admin credentials
3. **Add target groups** to organize your scan targets
4. **Create scan tasks** with custom Nmap configurations
5. **Execute scans** manually or schedule them for automatic execution
6. **View results** in the comprehensive report interface
7. **Manage users** through the admin interface (if you have admin privileges)

## Architecture

The application consists of several components:

- **Flask Web Application** - main web interface and API
- **APScheduler** - handles background scan execution and manages scheduled tasks
- **SQLite Database** - stores application data (users, targets, scan configurations, results)

## License

MIT License
