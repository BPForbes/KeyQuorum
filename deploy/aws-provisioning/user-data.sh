#!/bin/bash
set -euo pipefail

# KeyQuorum relay initial setup script
# This script runs as root on EC2 instance startup

DATA_VOLUME_DEVICE="${data_volume_device}"
DATA_MOUNT_POINT="${data_mount_point}"

# Logging setup
exec 1> >(logger -s -t keyquorum-userdata)
exec 2>&1

echo "Starting KeyQuorum relay initial setup..."

# Update system packages
apt-get update
apt-get upgrade -y

# Install dependencies
apt-get install -y \
    curl \
    wget \
    jq \
    git \
    build-essential \
    systemd-container \
    awscli \
    amazon-cloudwatch-agent \
    caddy

echo "System packages installed"

# Create keyquorum user and group
if ! id -u keyquorum &>/dev/null; then
    useradd -r -s /bin/bash -d /var/lib/keyquorum keyquorum
    echo "Created keyquorum user"
fi

# Wait for data volume to be attached
echo "Waiting for data volume to attach..."
for i in {1..60}; do
    if [ -b "$DATA_VOLUME_DEVICE" ]; then
        echo "Data volume found at $DATA_VOLUME_DEVICE"
        break
    fi
    echo "Waiting for $DATA_VOLUME_DEVICE... (attempt $i/60)"
    sleep 5
done

if [ ! -b "$DATA_VOLUME_DEVICE" ]; then
    echo "ERROR: Data volume not found at $DATA_VOLUME_DEVICE"
    exit 1
fi

# Format the data volume if not already formatted
if ! sudo blkid "$DATA_VOLUME_DEVICE" &>/dev/null; then
    echo "Formatting data volume..."
    mkfs.ext4 -F "$DATA_VOLUME_DEVICE"
else
    echo "Data volume already formatted"
fi

# Create mount point
mkdir -p "$DATA_MOUNT_POINT"

# Add to fstab for persistent mounting
if ! grep -q "$DATA_VOLUME_DEVICE" /etc/fstab; then
    echo "$DATA_VOLUME_DEVICE $DATA_MOUNT_POINT ext4 defaults,nofail 0 2" >> /etc/fstab
    echo "Added data volume to fstab"
fi

# Mount the volume
mount "$DATA_MOUNT_POINT" || true
echo "Data volume mounted at $DATA_MOUNT_POINT"

# Set permissions
chown -R keyquorum:keyquorum "$DATA_MOUNT_POINT"
chmod 0700 "$DATA_MOUNT_POINT"
echo "Set permissions for $DATA_MOUNT_POINT"

# Create necessary directories
mkdir -p "$DATA_MOUNT_POINT/database"
mkdir -p "$DATA_MOUNT_POINT/backup"
chown -R keyquorum:keyquorum "$DATA_MOUNT_POINT/database"
chown -R keyquorum:keyquorum "$DATA_MOUNT_POINT/backup"
chmod 0700 "$DATA_MOUNT_POINT/database"
chmod 0700 "$DATA_MOUNT_POINT/backup"

# Set up Caddy
echo "Configuring Caddy..."
mkdir -p /etc/caddy
mkdir -p /var/log/caddy

# Create a basic Caddyfile (will be updated during provisioning)
cat > /etc/caddy/Caddyfile <<'EOF'
# This is a placeholder; the real Caddyfile will be deployed during provisioning
# pointing to the actual relay domain
:443 {
    respond "Relay not yet configured" 503
}
EOF

chown caddy:caddy /etc/caddy/Caddyfile
chmod 0644 /etc/caddy/Caddyfile

# Enable and start Caddy (it will fail until Caddyfile is updated)
systemctl enable caddy || true
echo "Caddy service enabled"

# Set up CloudWatch Logs agent configuration
cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<'EOF'
{
  "agent": {
    "metrics_collection_interval": 300,
    "logfile": "/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log",
    "debug": false
  },
  "metrics": {
    "namespace": "KeyQuorum/Relay",
    "metrics_collected": {
      "disk": {
        "measurement": [
          {
            "name": "used_percent",
            "rename": "DiskUsagePercent"
          }
        ],
        "metrics_collection_interval": 300,
        "resources": ["/var/lib/keyquorum"],
        "drop_device": false
      },
      "mem": {
        "measurement": ["mem_used_percent"],
        "metrics_collection_interval": 300
      },
      "cpu": {
        "measurement": [
          {
            "name": "cpu_usage_system",
            "rename": "CPUUsageSystem"
          }
        ],
        "metrics_collection_interval": 300
      }
    }
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/syslog",
            "log_group_name": "/keyquorum/relay/syslog",
            "log_stream_name": "{instance_id}"
          },
          {
            "file_path": "/var/log/caddy/*.log",
            "log_group_name": "/keyquorum/relay/caddy",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
EOF

# Create log groups
mkdir -p /var/log/keyquorum
chown -R keyquorum:keyquorum /var/log/keyquorum
chmod 0755 /var/log/keyquorum

echo "CloudWatch agent configuration complete"

# Secure systemd settings
echo "Configuring systemd security..."
cat >> /etc/systemd/system.conf <<'EOF'

# KeyQuorum relay security hardening
DefaultTimeoutStopSec=30
EOF

systemctl daemon-reload

echo "KeyQuorum relay initial setup complete!"
echo "Waiting for provisioning script to complete setup..."
