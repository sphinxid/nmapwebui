# NmapWebUI

A web-based application that serves as a user-friendly wrapper for the Nmap network scanner. This application allows authenticated users to manage targets, define and execute Nmap scans, view scan reports, and schedule recurring scans.

## Features

- User Authentication & Authorization
- User Management
- Target Group Management
- Scan Task Creation & Configuration
- Asynchronous Background Scanning
- Task Listing & Management
- Scan Report Display
- Multiple Scan Runs & Report History
- Scheduled Scanning

## Prerequisites

- Python 3.8+
- Nmap installed on the system
- Redis server (for Celery task queue)
- (optional) Gunicorn or uWSGI for production deployment
- (optional) user running the flask & celery worker has sudo access without password for the nmap command that requires root privilege

## Installation

1. Clone the repository:
```
git clone <repository-url>
cd nmapwebui
```

2. Create a virtual environment and activate it:
```
python -m venv venv
source venv/bin/activate
```

3. Install the required packages:
```
pip install -r requirements.txt
```

4. Set up environment variables:
```
cp .env.example .env
```
Edit the `.env` file and set your configuration values.

5. Initialize the database:
```
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

6. Create an admin user:
```
python create_admin.py
```

## Running the Application

1. Start the Redis server:
```
redis-server
```

2. Start the Celery worker:
```
python run_celery.py
```

3. Start the Celery beat scheduler (for scheduled scans):
```
python run_celery_beat.py
```

4. Run the Flask application:
```
python run_app.py
```

5. Access the application at the URL shown in the console (default: http://127.0.0.1:5000)

## Configuration

The application uses environment variables for configuration. You can set these in the `.env` file:

```
# Flask configuration
FLASK_APP=run_app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key

# must use an absolute path (eg: /home/firman/nmapwebui/instance/app.db)
DATABASE_URL=sqlite:////home/firman/nmapwebui/instance/app.db

# Celery configuration
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Nmap configuration
NMAP_REPORTS_DIR=instance/reports

# Server configuration
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
```

## License

[MIT License](LICENSE)

## Running with Docker

This application can be built and run as a Docker container. The provided `Dockerfile` sets up the necessary environment, including Nmap, Redis, and all Python dependencies. Supervisor is used to manage the Gunicorn (Flask app), Celery worker, and Celery beat processes.

### Prerequisites for Docker

- Docker installed on your system.
- Ensure you have an `.env` file created (you can copy `.env.example`). See "Important Configuration for Docker" below.

### Building the Docker Image

To build the Docker image, navigate to the project root directory (where the `Dockerfile` is located) and run:

```bash
docker build -t nmapwebui .
```

### Important Configuration for Docker

Before running the container, you **must** update your `.env` file for the Docker environment:

1.  **`DATABASE_URL`**: Since SQLite is used and data should persist outside the container, this path should point to a location *inside* the container that will be mounted as a volume. The `Dockerfile` places the application in `/app`. A good value for the container is:
    `DATABASE_URL=sqlite:////app/instance/app.db`
2.  **`CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND`**: Redis runs inside the same container and is managed by Supervisor. So, these should point to the internal Redis instance:
    `CELERY_BROKER_URL=redis://localhost:6379/0`
    `CELERY_RESULT_BACKEND=redis://localhost:6379/0`
3.  **`NMAP_REPORTS_DIR`**: This should also point to a path inside the container that will be mounted:
    `NMAP_REPORTS_DIR=/app/instance/reports`

Ensure other variables like `SECRET_KEY` are set appropriately.

### Running the Docker Container

To run the Docker container:

```bash
docker run -d \
  --name nmapwebui-container \
  -p 5000:5000 \
  --env-file .env \
  -v ./instance:/app/instance \
  nmapwebui
```

**Explanation of `docker run` options:**

-   `-d`: Run the container in detached mode (in the background).
-   `--name nmapwebui-container`: Assign a name to the container.
-   `-p 5000:5000`: Map port 5000 on the host to port 5000 in the container (where Gunicorn is listening).
-   `--env-file .env`: Load environment variables from the `.env` file located in your project root on the host.
-   `-v ./instance:/app/instance`: Mount the `./instance` directory from your host into the `/app/instance` directory in the container. This is crucial for:
    -   Persisting the SQLite database (`app.db`).
    -   Persisting Nmap reports (if stored under `instance/reports` as per default config).
    Ensure the local `./instance` directory exists or Docker will create it as root.
-   `nmapwebui`: The name of the image you built.

After starting the container, the application should be accessible at `http://localhost:5000`.

### Accessing Logs

To view the logs from the running container (which includes output from Supervisor and the services it manages):

```bash
docker logs nmapwebui-container
```

To follow the logs in real-time:

```bash
docker logs -f nmapwebui-container
```
