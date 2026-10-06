#!/bin/bash
set -euo pipefail

# Provisioning script for KeyQuorum relay instance
# Usage: ./provision-instance.sh <instance-id> <aws-region>

INSTANCE_ID="${1:-}"
AWS_REGION="${2:-us-east-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$INSTANCE_ID" ]; then
    echo "Usage: $0 <instance-id> [aws-region]"
    echo "Example: $0 i-0123456789abcdef0 us-east-1"
    exit 1
fi

echo "KeyQuorum Relay Provisioning Script"
echo "===================================="
echo "Instance ID: $INSTANCE_ID"
echo "Region: $AWS_REGION"
echo ""

# Check prerequisites
echo "Checking prerequisites..."
for cmd in aws jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is not installed. Please install it and try again."
        exit 1
    fi
done

# Verify instance exists
echo "Verifying instance exists..."
if ! aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$AWS_REGION" \
    --query 'Reservations[0].Instances[0].State.Name' \
    --output text &>/dev/null; then
    echo "ERROR: Instance $INSTANCE_ID not found in region $AWS_REGION"
    exit 1
fi

# Get instance details
echo "Getting instance details..."
INSTANCE_INFO=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$AWS_REGION" \
    --query 'Reservations[0].Instances[0]')

INSTANCE_STATE=$(echo "$INSTANCE_INFO" | jq -r '.State.Name')
INSTANCE_IP=$(echo "$INSTANCE_INFO" | jq -r '.PublicIpAddress // .PrivateIpAddress')
INSTANCE_TYPE=$(echo "$INSTANCE_INFO" | jq -r '.InstanceType')

echo "Instance State: $INSTANCE_STATE"
echo "Instance Type: $INSTANCE_TYPE"
echo "Instance IP: $INSTANCE_IP"
echo ""

# Wait for instance to be running and SSM ready
echo "Waiting for instance to be ready..."
max_attempts=60
attempt=0
while [ $attempt -lt $max_attempts ]; do
    STATE=$(aws ec2 describe-instances \
        --instance-ids "$INSTANCE_ID" \
        --region "$AWS_REGION" \
        --query 'Reservations[0].Instances[0].State.Name' \
        --output text)

    if [ "$STATE" = "running" ]; then
        echo "Instance is running"
        break
    fi

    attempt=$((attempt + 1))
    echo "Waiting for instance to run... (attempt $attempt/$max_attempts)"
    sleep 5
done

if [ $attempt -eq $max_attempts ]; then
    echo "ERROR: Instance did not reach running state in time"
    exit 1
fi

# Wait for SSM agent to be ready
echo "Waiting for Systems Manager agent to be ready..."
attempt=0
while [ $attempt -lt $max_attempts ]; do
    STATUS=$(aws ssm describe-instance-information \
        --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
        --region "$AWS_REGION" \
        --query 'InstanceInformationList[0].PingStatus' \
        --output text 2>/dev/null || echo "Offline")

    if [ "$STATUS" = "Online" ]; then
        echo "Systems Manager agent is ready"
        break
    fi

    attempt=$((attempt + 1))
    echo "Waiting for SSM agent... Status: $STATUS (attempt $attempt/$max_attempts)"
    sleep 5
done

if [ $attempt -eq $max_attempts ]; then
    echo "WARNING: Systems Manager agent did not come online within timeout"
    echo "The instance may still be initializing. You can try again in a moment."
fi

echo ""
echo "✓ Instance is ready for provisioning"
echo ""
echo "Next steps:"
echo "1. Open a Session Manager session:"
echo "   aws ssm start-session --target $INSTANCE_ID --region $AWS_REGION"
echo ""
echo "2. In the session, verify the data volume is mounted:"
echo "   df -h /var/lib/keyquorum"
echo ""
echo "3. Copy the Caddyfile to the instance and configure Caddy:"
echo "   scp -P 22 /path/to/Caddyfile admin@$INSTANCE_IP:/tmp/Caddyfile"
echo "   # Then in the session:"
echo "   sudo cp /tmp/Caddyfile /etc/caddy/"
echo "   sudo systemctl reload caddy"
echo ""
echo "4. Install the relay binary:"
echo "   # Download or build the relay binary with --features provider"
echo "   scp -P 22 ./keyquorum admin@$INSTANCE_IP:/tmp/"
echo "   # In the session:"
echo "   sudo install -m 0755 /tmp/keyquorum /usr/local/bin/keyquorum-relay"
echo ""
echo "5. Set up the relay key credential (systemd-creds):"
echo "   # In the session:"
echo "   sudo systemctl edit keyquorum-relay  # Add LoadCredential= directive"
echo ""
echo "6. Start the relay:"
echo "   sudo systemctl start keyquorum-relay"
echo "   sudo systemctl status keyquorum-relay"
echo ""
echo "7. Verify the relay is responding:"
echo "   curl -k https://relay.example.com/health"
echo ""

# Optional: Offer to open a Session Manager session
read -p "Would you like to open a Session Manager session now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Opening Session Manager session..."
    aws ssm start-session --target "$INSTANCE_ID" --region "$AWS_REGION"
fi
