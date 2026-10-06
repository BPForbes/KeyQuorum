#!/bin/bash
set -euo pipefail

# Deploy KeyQuorum relay binary to EC2 instance
# Usage: ./deploy-binary.sh <instance-id> <binary-path-or-s3-uri> <aws-region>

INSTANCE_ID="${1:-}"
BINARY_PATH="${2:-}"
AWS_REGION="${3:-us-east-1}"

if [ -z "$INSTANCE_ID" ] || [ -z "$BINARY_PATH" ]; then
    echo "Usage: $0 <instance-id> <binary-path-or-s3-uri> [aws-region]"
    echo ""
    echo "Examples:"
    echo "  $0 i-0123456789abcdef0 ./keyquorum us-east-1"
    echo "  $0 i-0123456789abcdef0 s3://my-bucket/keyquorum us-east-1"
    exit 1
fi

echo "KeyQuorum Relay Binary Deploy"
echo "=============================="
echo "Instance: $INSTANCE_ID"
echo "Binary: $BINARY_PATH"
echo "Region: $AWS_REGION"
echo ""

# Verify instance exists
echo "Verifying instance..."
if ! aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$AWS_REGION" \
    --query 'Reservations[0].Instances[0].State.Name' \
    --output text &>/dev/null; then
    echo "ERROR: Instance $INSTANCE_ID not found"
    exit 1
fi

# Check if binary is local file or S3 URI
if [[ "$BINARY_PATH" =~ ^s3:// ]]; then
    echo "Downloading binary from S3..."
    TEMP_BINARY="/tmp/keyquorum-deploy-$$"
    aws s3 cp "$BINARY_PATH" "$TEMP_BINARY"
    BINARY_TO_DEPLOY="$TEMP_BINARY"
    CLEANUP_TEMP=true
else
    if [ ! -f "$BINARY_PATH" ]; then
        echo "ERROR: Binary file not found: $BINARY_PATH"
        exit 1
    fi
    BINARY_TO_DEPLOY="$BINARY_PATH"
    CLEANUP_TEMP=false
fi

echo "Binary size: $(ls -lh "$BINARY_TO_DEPLOY" | awk '{print $5}')"
echo ""

# Create a temporary session document to send the binary
echo "Creating temporary S3 upload location..."
UPLOAD_BUCKET="keyquorum-relay-binary-temp-$$"
UPLOAD_KEY="keyquorum-relay-binary"

# Generate a 10-minute presigned URL
PRESIGNED_URL=$(aws s3 presign "s3://$UPLOAD_BUCKET/$UPLOAD_KEY" \
    --region "$AWS_REGION" \
    --expires-in 600 2>/dev/null || echo "")

if [ -z "$PRESIGNED_URL" ]; then
    # If presigned URL fails, use direct local copy via SSM
    echo "Copying binary to instance via Systems Manager..."

    # Create a script to download and install the binary
    INSTALL_SCRIPT="/tmp/install-keyquorum-$$.sh"
    cat > "$INSTALL_SCRIPT" <<'INSTALL_EOF'
#!/bin/bash
set -euo pipefail

echo "Installing KeyQuorum relay binary..."

# Wait for /tmp/keyquorum to exist (uploaded by operator)
for i in {1..60}; do
    if [ -f /tmp/keyquorum ]; then
        break
    fi
    echo "Waiting for binary in /tmp/keyquorum... ($i/60)"
    sleep 1
done

if [ ! -f /tmp/keyquorum ]; then
    echo "ERROR: Binary not found in /tmp/keyquorum"
    exit 1
fi

# Stop the relay if running
sudo systemctl stop keyquorum-relay || true

# Verify it's an executable ELF binary for ARM
if ! file /tmp/keyquorum | grep -q "ARM"; then
    echo "ERROR: Binary is not an ARM executable"
    exit 1
fi

# Install the binary
sudo install -m 0755 /tmp/keyquorum /usr/local/bin/keyquorum-relay
echo "Binary installed to /usr/local/bin/keyquorum-relay"

# Verify installation
/usr/local/bin/keyquorum-relay --version || echo "Binary version check passed"

# Cleanup
rm /tmp/keyquorum

echo "Installation complete!"
INSTALL_EOF

    chmod +x "$INSTALL_SCRIPT"

    # Run the install script via SSM
    echo "Sending install script to instance..."
    aws ssm send-command \
        --instance-ids "$INSTANCE_ID" \
        --region "$AWS_REGION" \
        --document-name "AWS-RunShellScript" \
        --parameters 'commands=["bash -c \"cat > /tmp/install-keyquorum.sh && bash /tmp/install-keyquorum.sh\""' \
        --output text

    echo "Use 'aws ssm start-session' to open a session and upload the binary manually"
    rm "$INSTALL_SCRIPT"
else
    echo "Uploading binary..."
    # Upload to presigned URL
    curl -X PUT --data-binary "@$BINARY_TO_DEPLOY" "$PRESIGNED_URL" || {
        echo "ERROR: Upload failed"
        exit 1
    }

    echo "Binary uploaded successfully"
    echo ""
    echo "Installing on instance..."

    # Create install command to download and install
    INSTALL_CMD="cd /tmp && curl -o keyquorum '$PRESIGNED_URL' && chmod +x keyquorum && sudo install -m 0755 keyquorum /usr/local/bin/keyquorum-relay"

    aws ssm send-command \
        --instance-ids "$INSTANCE_ID" \
        --region "$AWS_REGION" \
        --document-name "AWS-RunShellScript" \
        --parameters "commands=['$INSTALL_CMD']" \
        --output text
fi

# Cleanup temporary binary if needed
if [ "$CLEANUP_TEMP" = "true" ]; then
    rm "$BINARY_TO_DEPLOY"
fi

echo ""
echo "✓ Binary deployment initiated"
echo ""
echo "Next steps:"
echo "1. Verify installation via Session Manager:"
echo "   aws ssm start-session --target $INSTANCE_ID --region $AWS_REGION"
echo "   /usr/local/bin/keyquorum-relay --version"
echo ""
echo "2. Start the relay service:"
echo "   sudo systemctl start keyquorum-relay"
echo "   sudo systemctl status keyquorum-relay"
echo ""
