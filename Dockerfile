# Use Python 3.9 slim image on Debian Bookworm
FROM python:3.9-slim-bookworm

# Set PYTHONUNBUFFERED to 1 to ensure print statements are sent straight to terminal
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update &&     apt-get install -y --no-install-recommends     nmap     redis-server     libpango-1.0-0     libpangoft2-1.0-0     libharfbuzz0b     libpangocairo-1.0-0     sudo     supervisor &&     # Create redis run and lib directories and ensure correct ownership
    mkdir -p /var/run/redis /var/lib/redis &&     chown -R redis:redis /var/run/redis /var/lib/redis &&     # Clean up apt cache
    rm -rf /var/lib/apt/lists/*

# Create a non-root user and group
RUN groupadd -r appgroup &&     useradd -r -g appgroup -d /home/appuser -s /bin/bash -m appuser &&     chown -R appuser:appgroup /home/appuser

# Set working directory
WORKDIR /app

# Copy requirements.txt and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire application source code into /app
# This includes entrypoint.sh which should be in the project root before this copy
COPY . .

# Make entrypoint.sh executable, it's now at /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Change ownership of /app to appuser:appgroup
RUN chown -R appuser:appgroup /app

# Create log directory for supervisor
RUN mkdir -p /var/log/supervisor &&     chown -R appuser:appgroup /var/log/supervisor

# Copy supervisor configuration (supervisord.conf should be in the project root before this copy)
# It will be copied to /app/supervisord.conf, then the next line copies it to the correct location.
# A bit redundant, could optimize by copying directly: COPY supervisord.conf /etc/supervisor/conf.d/
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose port
EXPOSE 5000

# Define entrypoint (entrypoint.sh is now in /app/entrypoint.sh)
ENTRYPOINT ["/app/entrypoint.sh"]

# Switch to non-root user
USER appuser

# Set default command
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
