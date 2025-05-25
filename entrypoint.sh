#!/bin/sh
set -e

# Change to the /app directory (this is usually the WORKDIR in the Dockerfile, but explicit doesn't hurt)
cd /app

DB_PATH="/app/instance/app.db"

# Check if the database file already exists
if [ ! -f "$DB_PATH" ]; then
    echo "Database file ($DB_PATH) not found. Running initial setup (migrations and admin user creation)..."

    # Run database migrations
    echo "Running database migrations..."
    # 'flask db init' creates the migrations folder if it doesn't exist.
    # It's generally idempotent, meaning it won't break if run multiple times.
    flask db init
    flask db migrate -m "Initial migration"
    flask db upgrade

    # Create admin user
    echo "Creating admin user..."
    python create_admin.py
else
    echo "Database file ($DB_PATH) already exists. Skipping initial setup."
fi

# Execute the main command passed as arguments to the script (e.g., supervisord)
echo "Executing CMD: $@"
exec "$@"
