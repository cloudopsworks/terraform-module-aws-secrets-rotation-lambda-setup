##
# (c) 2022-2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

data "aws_subnet" "lambda_sub" {
  count = try(var.settings.vpc.enabled, false) ? length(var.settings.vpc.subnets) : 0
  id    = var.settings.vpc.subnets[count.index]
}

resource "aws_security_group" "this" {
  count  = try(var.settings.vpc.create_security_group, false) && try(var.settings.vpc.enabled, false) ? 1 : 0
  name   = "${local.function_name}-sg"
  vpc_id = data.aws_subnet.lambda_sub[0].vpc_id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.all_tags
}