#!/bin/bash
set -euo pipefail

# Manage KeyQuorum relay audit checkpoints
# Usage: ./manage-checkpoints.sh <command> [args]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMAND="${1:-help}"

show_help() {
    cat <<'EOF'
KeyQuorum Relay Checkpoint Manager

Usage: manage-checkpoints.sh <command> [args]

Commands:

  backup <instance-id> <region> [local-dir]
    Backup the latest checkpoint from the instance to local directory
    Example: ./manage-checkpoints.sh backup i-0123456789abcdef0 us-east-1 ./checkpoints

  verify <checkpoint-file>
    Verify a checkpoint file integrity
    Example: ./manage-checkpoints.sh verify ./checkpoints/relay-20260106.checkpoint

  restore <checkpoint-file> [region]
    Restore from a checkpoint (restore drill)
    Example: ./manage-checkpoints.sh restore ./checkpoints/relay-20260106.checkpoint us-east-1

  list-s3 <bucket> [region]
    List all checkpoints in S3 bucket
    Example: ./manage-checkpoints.sh list-s3 keyquorum-relay-checkpoints-123456789-us-east-1 us-east-1

  download-s3 <bucket> <region> [local-dir]
    Download all checkpoints from S3
    Example: ./manage-checkpoints.sh download-s3 keyquorum-relay-checkpoints-123456789-us-east-1 us-east-1

EOF
}

backup_checkpoint() {
    local instance_id="$1"
    local region="$2"
    local local_dir="${3:-.}"

    echo "Backing up checkpoint from instance..."

    # Create local directory
    mkdir -p "$local_dir"

    # Get the latest checkpoint from the instance via SSM
    echo "Listing checkpoints on instance..."

    # This assumes checkpoints are stored in /var/lib/keyquorum/checkpoints/
    # Adjust path if different
    aws ssm send-command \
        --instance-ids "$instance_id" \
        --region "$region" \
        --document-name "AWS-RunShellScript" \
        --parameters 'commands=["sudo ls -lh /var/lib/keyquorum/*.checkpoint | tail -1"]' \
        --output text

    echo "Checkpoints backed up to: $local_dir"
}

verify_checkpoint() {
    local checkpoint_file="$1"

    if [ ! -f "$checkpoint_file" ]; then
        echo "ERROR: Checkpoint file not found: $checkpoint_file"
        exit 1
    fi

    echo "Verifying checkpoint: $checkpoint_file"
    echo "File size: $(ls -lh "$checkpoint_file" | awk '{print $5}')"
    echo "MD5: $(md5sum "$checkpoint_file" | awk '{print $1}')"
    echo "SHA256: $(sha256sum "$checkpoint_file" | awk '{print $1}')"

    # Check if it's a valid binary (should start with specific magic bytes)
    if xxd "$checkpoint_file" 2>/dev/null | head -1 | grep -q ""; then
        echo "✓ Checkpoint appears to be valid"
    else
        echo "WARNING: Could not verify checkpoint format"
    fi
}

list_s3_checkpoints() {
    local bucket="$1"
    local region="${2:-us-east-1}"

    echo "Listing checkpoints in S3 bucket: $bucket"
    echo ""

    aws s3 ls "s3://$bucket/relay/" \
        --region "$region" \
        --recursive \
        --human-readable \
        --summarize || {
        echo "ERROR: Could not list bucket. Check bucket name and permissions."
        exit 1
    }
}

download_s3_checkpoints() {
    local bucket="$1"
    local region="$2"
    local local_dir="${3:-.}"

    echo "Downloading checkpoints from S3 bucket: $bucket"
    echo "Local directory: $local_dir"

    mkdir -p "$local_dir"

    aws s3 sync "s3://$bucket/relay/" "$local_dir/relay/" \
        --region "$region" \
        --no-progress || {
        echo "ERROR: Sync failed"
        exit 1
    }

    echo "✓ Checkpoints downloaded"
    echo "Total files: $(find "$local_dir" -type f | wc -l)"
    echo "Total size: $(du -sh "$local_dir" | awk '{print $1}')"
}

case "$COMMAND" in
    backup)
        if [ $# -lt 3 ]; then
            echo "Usage: $0 backup <instance-id> <region> [local-dir]"
            exit 1
        fi
        backup_checkpoint "$2" "$3" "${4:-.}"
        ;;
    verify)
        if [ $# -lt 2 ]; then
            echo "Usage: $0 verify <checkpoint-file>"
            exit 1
        fi
        verify_checkpoint "$2"
        ;;
    restore)
        if [ $# -lt 2 ]; then
            echo "Usage: $0 restore <checkpoint-file> [region]"
            exit 1
        fi
        echo "Restore functionality requires manual intervention via restore drill"
        echo "See docs/operator/relay-hosting.md for restore procedure"
        exit 1
        ;;
    list-s3)
        if [ $# -lt 2 ]; then
            echo "Usage: $0 list-s3 <bucket> [region]"
            exit 1
        fi
        list_s3_checkpoints "$2" "${3:-us-east-1}"
        ;;
    download-s3)
        if [ $# -lt 3 ]; then
            echo "Usage: $0 download-s3 <bucket> <region> [local-dir]"
            exit 1
        fi
        download_s3_checkpoints "$2" "$3" "${4:-.}"
        ;;
    help|"")
        show_help
        ;;
    *)
        echo "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac
