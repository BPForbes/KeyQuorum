# AWS EC2 Relay Provisioning Kit

This kit provides Terraform infrastructure-as-code and provisioning scripts to deploy the KeyQuorum relay on AWS EC2 with an encrypted EBS volume and Caddy TLS termination.

## Prerequisites

### On your local machine

- AWS CLI v2 (configured with credentials and MFA)
- Terraform >= 1.0
- `jq` (for JSON parsing)

### AWS Account setup

- An AWS account with permissions to create EC2 instances, EBS volumes, KMS keys, IAM roles, S3 buckets, and CloudWatch resources
- MFA enabled on your AWS account
- A domain name to point to the relay instance (you'll provide the DNS record manually or via Route 53)

## What this kit provisions

### Compute
- **EC2 instance**: ARM-based (`t4g.small` ~$12/mo or `m7g.medium` ~$30/mo)
- **Root volume**: 20 GiB gp3 (standard OS)
- **Data volume**: 20 GiB gp3 encrypted with a customer-managed KMS key, mounted at `/var/lib/keyquorum`
- **Termination protection**: Enabled on the instance; data volume is retained on termination

### Security
- **Security group**: Inbound 443/tcp only (HTTPS), no SSH
- **KMS key**: Customer-managed key for EBS encryption and snapshot encryption
- **IAM roles**: Least-privilege roles for deployment, operation, backup, and restore
- **Session Manager**: Access via AWS Systems Manager (no SSH keys needed)

### Networking & DNS
- **Elastic IP**: Static public IP for the instance
- **A record**: Manual DNS configuration (instructions provided after apply)

### Storage & Monitoring
- **S3 bucket**: For audit checkpoints (write-once via Object Lock)
- **CloudWatch**: Alarms for high disk usage and stopped instance
- **EBS snapshots**: Lifecycle policy for hourly snapshots (7 days retention)

## Quick start

### 1. Initialize Terraform

```bash
cd deploy/aws-provisioning
terraform init
```

### 2. Customize variables

Copy `terraform.tfvars.example` to `terraform.tfvars` and edit it:

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit with your values
```

Required variables:
- `aws_region`: AWS region (e.g., `us-east-1`)
- `instance_type`: `t4g.small` (pilot) or `m7g.medium` (steady load)
- `relay_domain`: Domain name (e.g., `relay.example.com`)
- `operator_email`: Your email (for CloudWatch alarms)
- `environment_tag`: Label for resources (e.g., `prod` or `staging`)

### 3. Plan and apply

```bash
terraform plan -out=tfplan
terraform apply tfplan
```

Terraform will output:
- Instance ID and public IP
- Security group ID
- KMS key ARN
- S3 bucket for checkpoints
- Manual DNS configuration instructions

### 4. Configure DNS

After apply, update your DNS registrar or Route 53:
- Create an A record pointing `relay.example.com` to the Elastic IP (shown in Terraform output)
- Wait for DNS propagation (~5 minutes)

### 5. Provision the instance

Once DNS resolves:

```bash
./provision-instance.sh <instance-id> <aws-region>
```

This script will:
1. Wait for the instance to be ready
2. Copy the provisioning bundle to the instance
3. Run the setup scripts on the instance to:
   - Install system packages
   - Format and mount the encrypted data volume
   - Install Caddy
   - Install systemd unit for the relay
   - Configure CloudWatch agent (optional)

The script uses AWS Systems Manager Session Manager, so you don't need SSH access.

### 6. Deploy the relay binary

From the instance (via Session Manager):

```bash
aws s3 cp s3://your-relay-binary-bucket/keyquorum /tmp/keyquorum
sudo install -m 0755 /tmp/keyquorum /usr/local/bin/keyquorum-relay
```

Or use the provided helper:

```bash
./deploy-binary.sh <instance-id> <s3-uri-of-binary> <aws-region>
```

### 7. Decrypt the relay key and start the relay

On the instance (Session Manager):

```bash
sudo systemctl start keyquorum-relay
sudo systemctl status keyquorum-relay
```

The relay key is stored as a systemd encrypted credential. The systemd unit will prompt for the passphrase to decrypt it on startup.

### 8. Verify

```bash
curl -k https://relay.example.com/health
```

Should respond with `{"status":"ok"}` or similar.

## IAM roles and permissions

The kit creates four roles:

### Deploy role
Used during provisioning to create and configure resources.
- Launch EC2 instances
- Attach EBS volumes
- Modify security groups
- Upload binaries to S3

### Operate role
Day-to-day operations (MFA required).
- SSH via Session Manager (`ssm:StartSession`)
- Read CloudWatch logs and alarms
- Run `keyquorum host` commands

### Backup role
Automated backup operations (instance profile).
- Create EBS snapshots
- Write to S3 checkpoint bucket (write-once)

### Restore role
Used only during restore drills.
- Create volumes from snapshots
- Decrypt with KMS key
- (No access to production instance)

## Backup and restore

### Automatic backups

EBS snapshots are taken hourly via Lifecycle Manager.

To restore:

```bash
./restore-from-snapshot.sh <snapshot-id> <aws-region>
```

This creates an isolated volume in a test VPC for verification.

### Audit checkpoints

Daily:

```bash
sudo /usr/local/bin/keyquorum host keys checkpoint --out /mnt/checkpoint/relay-$(date +%Y%m%d).checkpoint
aws s3 cp /mnt/checkpoint/relay-*.checkpoint s3://your-checkpoint-bucket/relay/
```

The S3 bucket has Object Lock (write-once) to prevent accidental deletion.

## Monitoring and alerts

CloudWatch alarms notify you of:
- EBS volume > 80% usage
- Instance stopped (unexpected)
- High CPU (if applicable)
- Failed relay health check (custom metric)

Configure your email address in `terraform.tfvars` to receive alarm notifications.

## Cleanup

To destroy all provisioned resources:

```bash
terraform destroy
```

**Note:** This will:
- Terminate the EC2 instance
- Delete the security group
- Delete the S3 buckets
- Disable and delete the KMS key

The EBS snapshots and audit checkpoint bucket (Object Lock) are protected and require manual deletion.

## Troubleshooting

### Instance won't connect

1. Check instance is running: `aws ec2 describe-instances --instance-ids <id> --region <region>`
2. Check Session Manager is available: `aws ssm describe-instance-information --region <region>`
3. Verify IAM role has `AmazonSSMManagedInstanceCore` policy

### DNS not resolving

1. Verify the A record is created at your registrar or Route 53
2. Wait for TTL to expire (~5 minutes)
3. Test: `nslookup relay.example.com`

### Relay won't start

1. Check logs: `sudo journalctl -u keyquorum-relay -n 50`
2. Verify the relay key credential: `sudo systemd-creds list`
3. Ensure binary has correct permissions: `ls -la /usr/local/bin/keyquorum-relay`

### Data volume not mounted

1. Check mount: `df -h /var/lib/keyquorum`
2. Check journal: `sudo journalctl -u var-lib-keyquorum.mount -n 20`
3. Manual mount: `sudo mount /dev/nvme1n1p1 /var/lib/keyquorum`

## Security notes

- Never commit `terraform.tfvars` with real values to Git
- The operator lock (`kql_…`) is never stored on the instance; bring it in Session Manager only
- Provider root key is offline-only; never put it on the instance
- Audit checkpoints are the only records you're keeping; store them securely
- Enable MFA on the Operate role IAM user before production use

## Next steps

1. **Operator lock ceremony** (offline): `host keys` mints the initial operator lock
2. **Provider certificate** (offline): `host certify` issues the relay identity
3. **Upload the relay binary**: Build with `--features provider` and upload to S3
4. **First customer key**: `host keys create --recipient-key ...` seals the customer's first bearer
5. **Configure Cloudflare** (optional): Use `deploy/cloudflare/cloudflared-config.example.yml` if you want edge caching and DDoS protection

See `docs/operator/relay-deployment.md` for the complete operator runbook.
