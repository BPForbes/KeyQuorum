# Quick Start: AWS EC2 Relay Provisioning

This guide gets you from zero to a running KeyQuorum relay on AWS EC2 in about 30 minutes.

## Prerequisites (install locally)

```bash
# macOS
brew install terraform aws-cli jq

# Ubuntu/Debian
sudo apt-get install terraform awscli jq

# Windows
choco install terraform awscli jq
```

Configure AWS credentials:
```bash
aws configure
# Enter your access key, secret key, region (e.g., us-east-1)
# IMPORTANT: Enable MFA on your AWS account before production use
```

## 1. Customize variables (2 minutes)

```bash
cd deploy/aws-provisioning
cp terraform.tfvars.example terraform.tfvars
# Edit with your values
```

Required fields in `terraform.tfvars`:
- `relay_domain`: Your relay domain (e.g., `relay.example.com`)
- `operator_email`: Your email for alerts (e.g., `ops@example.com`)
- `aws_region`: AWS region (e.g., `us-east-1`)
- `instance_type`: `t4g.small` (pilot) or `m7g.medium` (production)

## 2. Deploy infrastructure (5 minutes)

```bash
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

Save the outputs, especially:
- Instance ID (e.g., `i-0123456789abcdef0`)
- Elastic IP
- DNS setup instructions

## 3. Configure DNS (2 minutes)

Create an A record at your DNS registrar or Route 53:
```
relay.example.com  A  <Elastic IP from Terraform output>
```

Wait for DNS to propagate (usually 5 minutes):
```bash
nslookup relay.example.com
```

## 4. Provision the instance (10 minutes)

```bash
./provision-instance.sh <instance-id> <aws-region>
```

Example:
```bash
./provision-instance.sh i-0123456789abcdef0 us-east-1
```

This script will:
- Wait for the instance to be ready
- Check Systems Manager is online
- Output next steps for manual installation

## 5. Install the relay binary

Open a Session Manager session:
```bash
aws ssm start-session --target i-0123456789abcdef0 --region us-east-1
```

In the session:
```bash
# Verify data volume is mounted
df -h /var/lib/keyquorum

# Download or upload the relay binary
# (Build it locally with: cargo build --release --features provider)
scp ./keyquorum <instance>:/tmp/

# Install (in the session)
sudo install -m 0755 /tmp/keyquorum /usr/local/bin/keyquorum-relay
```

## 6. Configure the relay key

The relay identity key (private) must be stored securely. On the instance:

```bash
# Store the relay key via systemd-creds (encrypted at rest)
echo -n "your-relay-private-key-hex" | sudo systemd-creds encrypt - --with=tpm2 /tmp/relay.key

# Or without TPM:
echo -n "your-relay-private-key-hex" | sudo systemd-creds encrypt - /tmp/relay.key

# Edit the systemd unit to load it
sudo systemctl edit keyquorum-relay
# Add: LoadCredential=relay_key:/tmp/relay.key
```

## 7. Start the relay

In the Session Manager session:
```bash
sudo systemctl start keyquorum-relay
sudo systemctl status keyquorum-relay
sudo journalctl -u keyquorum-relay -n 50
```

## 8. Verify it's running

```bash
curl -k https://relay.example.com/health
```

Should respond with status info (exact format depends on implementation).

## Key files in this directory

| File | Purpose |
| --- | --- |
| `README.md` | Full documentation with architecture details |
| `variables.tf` | Input variables (AWS region, instance type, etc.) |
| `main.tf` | Primary AWS resources (EC2, EBS, KMS, etc.) |
| `iam.tf` | IAM roles and policies |
| `security.tf` | Security groups |
| `outputs.tf` | Terraform outputs |
| `provision-instance.sh` | Initial instance setup script |
| `deploy-binary.sh` | Deploy relay binary to instance |
| `manage-checkpoints.sh` | Backup and restore audit checkpoints |
| `restore-from-snapshot.sh` | Restore drill from EBS snapshots |

## Cleanup

When done with testing, destroy everything:
```bash
terraform destroy
```

**Note:** This destroys the EC2 instance and data volume. EBS snapshots and S3 checkpoint buckets (with Object Lock) must be deleted manually for safety.

## Troubleshooting

### Instance won't connect via Session Manager
1. Verify instance is running: `aws ec2 describe-instances --instance-ids <id> --region <region>`
2. Wait 2-3 minutes for SSM agent to start
3. Check IAM permissions: Instance profile must have `AmazonSSMManagedInstanceCore`

### Data volume not mounted
```bash
# In the session:
df -h  # Check if /var/lib/keyquorum is listed
sudo systemctl status var-lib-keyquorum.mount  # Check mount service
sudo mount /var/lib/keyquorum  # Manual mount if needed
```

### Relay won't start
```bash
# Check logs:
sudo journalctl -u keyquorum-relay -n 100

# Verify binary exists:
ls -la /usr/local/bin/keyquorum-relay

# Check relay key credential:
sudo systemctl cat keyquorum-relay
```

### DNS not resolving
1. Verify A record created: `nslookup relay.example.com`
2. Check Terraform output for correct Elastic IP
3. Wait longer for DNS TTL expiry

## Next steps

1. **Set up backups:** Enable automated EBS snapshots (Terraform creates the lifecycle policy)
2. **Configure Caddy:** Create a proper Caddyfile with your relay domain and TLS settings
3. **Issue first customer key:** Run `keyquorum host keys create --recipient-key ...` offline, then `loadkey` on the relay
4. **Enable monitoring:** CloudWatch alarms are set up; verify email subscriptions
5. **Document your setup:** Record the instance ID, volume IDs, and KMS key ARN for your runbook

## Security notes

- **Never commit `terraform.tfvars`** with real AWS credentials or domain names
- **The operator lock** (`kql_…`) stays offline; pass it to the relay only in Session Manager
- **The provider root key** is offline-only; never put it on the instance
- **Enable MFA** on the Operate and Deploy IAM roles before production
- **Rotate API keys** regularly (see `relay-deployment.md`)
- **Store checkpoints securely** off the relay (the S3 bucket with Object Lock helps)

## Support

- Full documentation: `docs/operator/relay-deployment.md`
- Architecture and decisions: `docs/operator/relay-hosting.md`
- Security model: `docs/operator/relay-secrets.md`
