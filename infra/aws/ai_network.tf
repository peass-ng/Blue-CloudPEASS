# Isolated agent tasks have no route to another VPC and cannot initiate traffic
# to private/link-local networks. The task also has no IAM task role: metadata
# services never supply the platform worker's credentials to either container.
resource "aws_subnet" "ai" {
  vpc_id                  = aws_vpc.cspm.id
  cidr_block              = "10.253.0.64/26"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.name}-ai" }
}
resource "aws_route_table_association" "ai" {
  subnet_id      = aws_subnet.ai.id
  route_table_id = aws_route_table.tasks.id
}
resource "aws_security_group" "ai" {
  name   = "${local.name}-ai"
  vpc_id = aws_vpc.cspm.id
  dynamic "egress" {
    for_each = toset([443, 6443])
    content {
      from_port   = egress.value
      to_port     = egress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
resource "aws_network_acl" "ai" {
  vpc_id     = aws_vpc.cspm.id
  subnet_ids = [aws_subnet.ai.id]
  tags       = { Name = "${local.name}-ai" }
  dynamic "egress" {
    for_each = { for index, cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"] : index => cidr }
    content {
      rule_no    = 100 + tonumber(egress.key)
      protocol   = "-1"
      action     = "deny"
      cidr_block = egress.value
      from_port  = 0
      to_port    = 0
    }
  }
  dynamic "egress" {
    for_each = { "200" = 443, "201" = 6443 }
    content {
      rule_no    = tonumber(egress.key)
      protocol   = "tcp"
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = egress.value
      to_port    = egress.value
    }
  }
  ingress {
    rule_no    = 200
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }
}
