locals {
  project_name = "cloud-control-plane-defense"
  vpc_cidr     = "10.40.0.0/16"

  public_subnets = {
    public_a = {
      cidr = "10.40.1.0/24"
      az   = "eu-north-1a"
    }
    public_b = {
      cidr = "10.40.2.0/24"
      az   = "eu-north-1b"
    }
  }

  private_subnets = {
    private_a = {
      cidr = "10.40.11.0/24"
      az   = "eu-north-1a"
    }
    private_b = {
      cidr = "10.40.12.0/24"
      az   = "eu-north-1b"
    }
  }

  common_tags = {
    Project     = local.project_name
    Environment = "security-lab"
    ManagedBy   = "Terraform"
  }
}

resource "aws_vpc" "main" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "${local.project_name}-vpc"
  })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${local.project_name}-igw"
  })
}

resource "aws_subnet" "public" {
  for_each = local.public_subnets

  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${local.project_name}-${each.key}"
    Tier = "public"
  })
}

resource "aws_subnet" "private" {
  for_each = local.private_subnets

  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "${local.project_name}-${each.key}"
    Tier = "private"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${local.project_name}-public-rt"
    Tier = "public"
  })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${local.project_name}-private-rt"
    Tier = "private"
  })
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "application" {
  name        = "${local.project_name}-application"
  description = "HTTPS ingress only from designated public subnets"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from public subnet tier"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [
      for subnet in local.public_subnets : subnet.cidr
    ]
  }

  egress {
    description = "Outbound IPv4 traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.project_name}-application-sg"
  })
}

output "vpc_id" {
  description = "ID of the project VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = { for key, subnet in aws_subnet.public : key => subnet.id }
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = { for key, subnet in aws_subnet.private : key => subnet.id }
}

output "application_security_group_id" {
  description = "ID of the application security group"
  value       = aws_security_group.application.id
}
