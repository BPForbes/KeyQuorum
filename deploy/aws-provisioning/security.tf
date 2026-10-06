# Security group for the relay
resource "aws_security_group" "relay" {
  name        = "keyquorum-relay-sg"
  description = "Security group for KeyQuorum relay (HTTPS only, no SSH)"

  # Inbound HTTPS from anywhere (or specific CIDR blocks)
  dynamic "ingress" {
    for_each = var.inbound_cidrs
    content {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
      description = "HTTPS from ${ingress.value}"
    }
  }

  # Inbound HTTP for ACME challenge (Caddy)
  dynamic "ingress" {
    for_each = var.inbound_cidrs
    content {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
      description = "HTTP from ${ingress.value} (ACME challenge)"
    }
  }

  # Outbound to package repositories and Let's Encrypt
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to anywhere (package repos, Let's Encrypt)"
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP to anywhere (package repos)"
  }

  # Outbound DNS
  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS (UDP)"
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS (TCP)"
  }

  tags = {
    Name = "keyquorum-relay-sg"
  }
}

# Egress to AWS Systems Manager for Session Manager
resource "aws_security_group_rule" "ssm_egress" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.relay.id
  description       = "HTTPS to AWS for Systems Manager"
}

# No inbound SSH (Session Manager access only)
