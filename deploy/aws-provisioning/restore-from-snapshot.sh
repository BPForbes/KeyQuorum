#!/bin/bash
set -euo pipefail

# Restore from EBS snapshot for disaster recovery drill
# Usage: ./restore-from-snapshot.sh <snapshot-id> [aws-region]

SNAPSHOT_ID="${1:-}"
AWS_REGION="${2:-us-east-1}"

if [ -z "$SNAPSHOT_ID" ]; then
    echo "Usage: $0 <snapshot-id> [aws-region]"
    echo ""
    echo "This script creates an isolated restore environment for a disaster recovery drill."
    echo ""
    echo "Steps:"
    echo "1. Find a recent snapshot:"
    echo "   aws ec2 describe-snapshots --owner-ids self --region $AWS_REGION --query 'Snapshots[?Tags[?Key==\`SnapshotSchedule\`]].{ID:SnapshotId,StartTime:StartTime,Size:VolumeSize}' --output table"
    echo ""
    echo "2. Run this script:"
    echo "   $0 snap-0123456789abcdef0 $AWS_REGION"
    exit 1
fi

echo "KeyQuorum Relay Restore Drill"
echo "============================="
echo "Snapshot ID: $SNAPSHOT_ID"
echo "Region: $AWS_REGION"
echo ""
echo "WARNING: This creates an isolated test environment."
echo "It is NOT connected to production."
echo ""

# Verify snapshot exists
echo "Verifying snapshot..."
SNAPSHOT_INFO=$(aws ec2 describe-snapshots \
    --snapshot-ids "$SNAPSHOT_ID" \
    --region "$AWS_REGION" \
    --query 'Snapshots[0]' 2>/dev/null || echo "{}")

if [ "$SNAPSHOT_INFO" = "{}" ]; then
    echo "ERROR: Snapshot not found: $SNAPSHOT_ID"
    exit 1
fi

SNAPSHOT_STATE=$(echo "$SNAPSHOT_INFO" | jq -r '.State')
SNAPSHOT_SIZE=$(echo "$SNAPSHOT_INFO" | jq -r '.VolumeSize')
SNAPSHOT_START=$(echo "$SNAPSHOT_INFO" | jq -r '.StartTime')

echo "Snapshot State: $SNAPSHOT_STATE"
echo "Volume Size: ${SNAPSHOT_SIZE} GiB"
echo "Created: $SNAPSHOT_START"
echo ""

if [ "$SNAPSHOT_STATE" != "completed" ]; then
    echo "ERROR: Snapshot is not in completed state: $SNAPSHOT_STATE"
    exit 1
fi

# Create volume from snapshot
echo "Creating volume from snapshot..."
VOLUME_ID=$(aws ec2 create-volume \
    --snapshot-id "$SNAPSHOT_ID" \
    --region "$AWS_REGION" \
    --availability-zone "${AWS_REGION}a" \
    --tag-specifications "ResourceType=volume,Tags=[{Key=Name,Value=keyquorum-relay-restore-drill},{Key=Environment,Value=test}]" \
    --query 'VolumeId' \
    --output text)

echo "Created volume: $VOLUME_ID"
echo ""

# Wait for volume to be available
echo "Waiting for volume to be available..."
max_attempts=60
attempt=0
while [ $attempt -lt $max_attempts ]; do
    STATE=$(aws ec2 describe-volumes \
        --volume-ids "$VOLUME_ID" \
        --region "$AWS_REGION" \
        --query 'Volumes[0].State' \
        --output text)

    if [ "$STATE" = "available" ]; then
        echo "Volume is available"
        break
    fi

    attempt=$((attempt + 1))
    echo "Waiting for volume... (attempt $attempt/$max_attempts, state: $STATE)"
    sleep 5
done

if [ $attempt -eq $max_attempts ]; then
    echo "ERROR: Volume did not become available in time"
    exit 1
fi

# Get volume details
VOLUME_INFO=$(aws ec2 describe-volumes \
    --volume-ids "$VOLUME_ID" \
    --region "$AWS_REGION" \
    --query 'Volumes[0]')

VOLUME_SIZE=$(echo "$VOLUME_INFO" | jq -r '.Size')
VOLUME_AZ=$(echo "$VOLUME_INFO" | jq -r '.AvailabilityZone')

echo ""
echo "✓ Restore volume ready"
echo ""
echo "Volume Details:"
echo "  ID: $VOLUME_ID"
echo "  Size: ${VOLUME_SIZE} GiB"
echo "  Availability Zone: $VOLUME_AZ"
echo ""
echo "Next steps:"
echo ""
echo "1. Create a test EC2 instance in the same AZ:"
echo "   aws ec2 run-instances --image-id ami-0c55b159cbfafe1f0 --instance-type t4g.small \\"
echo "     --key-name your-key --region $AWS_REGION --subnet-id subnet-xxxxx"
echo ""
echo "2. Attach this volume to the test instance:"
echo "   aws ec2 attach-volume --volume-id $VOLUME_ID --instance-id i-xxxxx \\"
echo "     --device /dev/sdf --region $AWS_REGION"
echo ""
echo "3. SSH into the instance and mount the volume:"
echo "   sudo mkdir -p /mnt/restore"
echo "   sudo mount /dev/nvme1n1 /mnt/restore"
echo ""
echo "4. Verify the database:"
echo "   sudo sqlite3 /mnt/restore/relay.sqlite '.tables'"
echo ""
echo "5. Run verification commands:"
echo "   /usr/local/bin/keyquorum host keys events --verify"
echo ""
echo "6. After verification, clean up:"
echo "   aws ec2 detach-volume --volume-id $VOLUME_ID --region $AWS_REGION"
echo "   aws ec2 delete-volume --volume-id $VOLUME_ID --region $AWS_REGION"
echo ""
echo "   Terminate the test instance when done"
echo ""

# Offer to cleanup
read -p "Continue with another restore, or cleanup this volume? (c/l) " -n 1 -r
echo
if [[ $REPLY =~ ^[Ll]$ ]]; then
    echo "Cleaning up volume..."
    aws ec2 delete-volume --volume-id "$VOLUME_ID" --region "$AWS_REGION"
    echo "✓ Volume deleted"
fi
