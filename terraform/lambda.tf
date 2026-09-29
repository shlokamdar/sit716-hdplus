data "archive_file" "add_block_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda/add_block.zip"

  source {
    content  = file("${path.module}/lambda/add_block.py")
    filename = "add_block.py"
  }

  source {
    content  = file("${path.module}/lambda/blocklist_utils.py")
    filename = "blocklist_utils.py"
  }
}


resource "aws_lambda_function" "add_block" {
  function_name = "ids-add-block"

  role    = aws_iam_role.detection_engine_role.arn
  handler = "add_block.handler"
  runtime = "python3.12"

  timeout = 10

  filename         = data.archive_file.add_block_zip.output_path
  source_code_hash = data.archive_file.add_block_zip.output_base64sha256

  environment {
    variables = {
      TARGET_SG_ID = aws_security_group.target_sg.id

      # Target subnet NACL used for network-level deny enforcement.
      TARGET_NACL_ID = aws_network_acl.target_nacl.id

      WHITELIST_CIDRS = var.target_sg_cidr
    }
  }

  tags = {
    Name = "IDS-Add-Block"
  }
}

data "archive_file" "remove_expired_blocks_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda/remove_expired_blocks.zip"

  source {
    content  = file("${path.module}/lambda/remove_expired_blocks.py")
    filename = "remove_expired_blocks.py"
  }

  source {
    content  = file("${path.module}/lambda/blocklist_utils.py")
    filename = "blocklist_utils.py"
  }
}


resource "aws_lambda_function" "remove_expired_blocks" {
  function_name = "ids-remove-expired-blocks"

  role    = aws_iam_role.detection_engine_role.arn
  handler = "remove_expired_blocks.handler"
  runtime = "python3.12"

  timeout = 30

  filename         = data.archive_file.remove_expired_blocks_zip.output_path
  source_code_hash = data.archive_file.remove_expired_blocks_zip.output_base64sha256

  environment {
    variables = {
      TARGET_SG_ID = aws_security_group.target_sg.id

      # Same target subnet NACL used when removing expired deny entries.
      TARGET_NACL_ID = aws_network_acl.target_nacl.id
    }
  }

  tags = {
    Name = "IDS-Remove-Expired-Blocks"
  }
}

resource "aws_cloudwatch_event_rule" "expire_blocks_schedule" {
  name = "ids-expire-blocks-schedule"

  description = "Checks for expired IDS blocks every minute"

  schedule_expression = "rate(1 minute)"
}


resource "aws_cloudwatch_event_target" "expire_blocks_target" {
  rule      = aws_cloudwatch_event_rule.expire_blocks_schedule.name
  target_id = "remove-expired-blocks"
  arn       = aws_lambda_function.remove_expired_blocks.arn
}


resource "aws_lambda_permission" "allow_eventbridge_invoke" {
  statement_id = "AllowEventBridgeInvoke"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.remove_expired_blocks.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.expire_blocks_schedule.arn
}
