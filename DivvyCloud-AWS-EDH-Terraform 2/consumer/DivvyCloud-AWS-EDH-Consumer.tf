/*
AWS - EDH - Consumer
Author: Brendan Elliott
Date:   04/22/20
Ver:    1.1
*/

// Random string generator
resource "random_string" "DivvyCloud-Random-Short" {
  length = 6
  special = false
  number = false
  upper = false
}

resource "aws_iam_policy" "DivvyCloud-Consumer-Role-Policy" {
  name        = "DivvyCloud-EDH-Consumer"
  description = "DivvyCloud EDH Consumer Policy"

  //policy = file("${path.module}/policies/consumer-policy.json")
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "events:DeleteRule",
                "events:DescribeRule",
                "events:PutRule",
                "events:PutTargets",
                "events:RemoveTargets"
            ],
            "Resource": "arn:aws:events:${var.region}:${var.consumer_account_id}:rule/divvycloud*"
        },
        {

            "Effect": "Allow",
            "Action": [
                "sqs:ListQueues",
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
                "sqs:DeleteMessageBatch"
            ],
            "Resource": [
                "${aws_sqs_queue.DivvyCloud-Consumer-SQS.arn}"
            ]
        },
        {
            "Action": [
                "organizations:DescribeOrganization"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "DivvyCloud-Consumer-Role-Attach" {
  role       = var.divvycloud_role_name
  policy_arn = aws_iam_policy.DivvyCloud-Consumer-Role-Policy.arn
}

// CloudWatch event bus org permission 
resource "aws_cloudwatch_event_permission" "OrganizationAccess" {
  principal    = "*"
  statement_id = "OrganizationAccess"

  condition {
    key   = "aws:PrincipalOrgID"
    type  = "StringEquals"
    value = var.organization_id
  }
}

// Consumer CloudTrail S3 bucket
resource "aws_s3_bucket" "DivvyCloud-Consumer-CloudTrail-S3" {
  bucket                      = "divvycloud-edh-consumer-${var.consumer_account_id}"
  force_destroy               = true
  region                      = var.region
  request_payer               = "BucketOwner"
  tags                        = {}

  versioning {
      enabled    = false
      mfa_delete = false
  }
  }

resource "aws_s3_bucket_policy" "DivvyCloud-Consumer-CloudTrail-S3-Policy" {
  bucket = aws_s3_bucket.DivvyCloud-Consumer-CloudTrail-S3.bucket
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "${aws_s3_bucket.DivvyCloud-Consumer-CloudTrail-S3.arn}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "${aws_s3_bucket.DivvyCloud-Consumer-CloudTrail-S3.arn}/AWSLogs/${var.consumer_account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
EOF
}

// Consumer EDH CloudTrail
resource "aws_cloudtrail" "DivvyCloud-Consumer-CloudTrail" {
    depends_on                    = [aws_s3_bucket_policy.DivvyCloud-Consumer-CloudTrail-S3-Policy]
    include_global_service_events = true
    is_multi_region_trail         = true
    is_organization_trail         = false
    // Encrypt logs files?
    kms_key_id                    = aws_kms_key.DivvyCloud-Consumer-CloudTrail-KMS.arn
    name                          = "DivvyCloud-Consumer-CloudTrail-${var.consumer_account_id}"
    s3_bucket_name                = aws_s3_bucket.DivvyCloud-Consumer-CloudTrail-S3.bucket
    event_selector {
      read_write_type             = "WriteOnly"
      include_management_events   = true
    }
}

resource "aws_kms_alias" "DivvyCloud-Consumer-CloudTrail-KMS-Alias" {
  name          = "alias/DivvyCloud-Consumer-CloutTrail-KMS-${random_string.DivvyCloud-Random-Short.result}"
  target_key_id = aws_kms_key.DivvyCloud-Consumer-CloudTrail-KMS.id
}

resource "aws_kms_key" "DivvyCloud-Consumer-CloudTrail-KMS" {
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  description              = "The key created by DivvyCloud to encrypt CloudTrail log files"
  enable_key_rotation      = true
  is_enabled               = true
  key_usage                = "ENCRYPT_DECRYPT"
  policy                   = <<EOF
{
    "Version": "2012-10-17",
    "Id": "Key policy created by CloudTrail",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::${var.consumer_account_id}:root"
                ]
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow CloudTrail to encrypt logs",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "kms:GenerateDataKey*",
            "Resource": "*",
            "Condition": {
                "StringLike": {
                    "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${var.consumer_account_id}:trail/*"
                }
            }
        },
        {
            "Sid": "Allow CloudTrail to describe key",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "kms:DescribeKey",
            "Resource": "*"
        },
        {
            "Sid": "Allow principals in the account to decrypt log files",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
                "kms:Decrypt",
                "kms:ReEncryptFrom"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:CallerAccount": "${var.consumer_account_id}"
                },
                "StringLike": {
                    "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${var.consumer_account_id}:trail/*"
                }
            }
        },
        {
            "Sid": "Allow alias creation during setup",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": "kms:CreateAlias",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": "ec2.${var.region}.amazonaws.com",
                    "kms:CallerAccount": "${var.consumer_account_id}"
                }
            }
        },
        {
            "Sid": "Enable cross account log decryption",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
                "kms:Decrypt",
                "kms:ReEncryptFrom"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:CallerAccount": "${var.consumer_account_id}"
                },
                "StringLike": {
                    "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${var.consumer_account_id}:trail/*"
                }
            }
        }
    ]
}
EOF
}

resource "aws_kms_alias" "DivvyCloud-Consumer-SQS-KMS-Alias" {
  name          = "alias/DivvyCloud-Consumer-SQS-KMS-${random_string.DivvyCloud-Random-Short.result}"
  target_key_id = aws_kms_key.DivvyCloud-Consumer-SQS-KMS.id
}

resource "aws_kms_key" "DivvyCloud-Consumer-SQS-KMS" {
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  description              = "The key created by DivvyCloud to encrypt SQS messages"
  enable_key_rotation      = true
  is_enabled               = true
  key_usage                = "ENCRYPT_DECRYPT"
  policy                   = <<EOF
{
    "Version": "2012-10-17",
    "Id": "auto-sqs-1",
    "Statement": [
        {
            "Sid": "Allow access through Simple Queue Service (SQS) for all principals in the account that are authorized to use SQS",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:CreateGrant",
                "kms:DescribeKey"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": "sqs.${var.region}.amazonaws.com",
                    "kms:CallerAccount": "${var.consumer_account_id}"
                }
            }
        },
        {
            "Sid": "Allow direct access to key metadata to the account",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${var.consumer_account_id}:root"
            },
            "Action": [
                "kms:EnableKeyRotation",
                "kms:Describe*",
                "kms:Get*",
                "kms:List*",
                "kms:RevokeGrant",
                "kms:CreateKey",
                "kms:PutKeyPolicy",
                "kms:ScheduleKeyDeletion",
                "kms:CreateAlias",
                "kms:DeleteAlias"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "events.amazonaws.com"
            },
            "Action": [
                "kms:GenerateDataKey",
                "kms:Decrypt"
            ],
            "Resource": "arn:aws:kms:${var.region}:${var.consumer_account_id}:key/*"
        }
    ]
}
EOF
}

resource "aws_sqs_queue" "DivvyCloud-Consumer-SQS" {
  content_based_deduplication       = true
  delay_seconds                     = 0
  fifo_queue                        = true
  kms_master_key_id                 = aws_kms_key.DivvyCloud-Consumer-SQS-KMS.arn
  kms_data_key_reuse_period_seconds = 300
  max_message_size                  = 262144
  message_retention_seconds         = 86400
  name                              = "divvycloud-event-aggregator-${var.license_fingerprint}.fifo"
}

resource "aws_sqs_queue_policy" "DivvyCloud-Consumer-SQS-Policy" {
  queue_url = aws_sqs_queue.DivvyCloud-Consumer-SQS.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.DivvyCloud-Consumer-SQS.arn}",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "arn:aws:events:${var.region}:${var.consumer_account_id}:rule/divvycloud-root-producer-${var.license_fingerprint}*"
        }
      }
    }
  ]
}
EOF
}

/*
// Consumer CloudWatch rules
resource "aws_cloudwatch_event_rule" "DivvyCloud-EDH-CloudWatch-Consumer-Rule-EC2-0" {
    description   = "divvycloud Event Driven Harvesting EC2-0"
    event_pattern = file("${path.module}/policies/events-EC2-0.json")
    is_enabled    = true
    name          = "divvycloud-root-consumer-${var.license_fingerprint}-EC2-0"
    tags          = {}
}

resource "aws_cloudwatch_event_rule" "DivvyCloud-EDH-CloudWatch-Consumer-Rule-EC2-1" {
    description   = "divvycloud Event Driven Harvesting EC2-1"
    event_pattern = file("${path.module}/policies/events-EC2-1.json")
    is_enabled    = true
    name          = "divvycloud-root-consumer-${var.license_fingerprint}-EC2-1"
    tags          = {}
}

resource "aws_cloudwatch_event_rule" "DivvyCloud-EDH-CloudWatch-Consumer-Rule-ECR-ECS-R53-CFT" {
    description   = "divvycloud Event Driven Harvesting ECR-ECS-R53-CFT"
    event_pattern = file("${path.module}/policies/events-ECR-ECS-R53-CFT.json")
    is_enabled    = true
    name          = "divvycloud-root-consumer-${var.license_fingerprint}-ECR-ECS-R53-CFT"
    tags          = {}
}

resource "aws_cloudwatch_event_rule" "DivvyCloud-EDH-CloudWatch-Consumer-Rule-REDSHIFT-ASG-RDS-EC-ES" {
    description   = "divvycloud Event Driven Harvesting REDSHIFT-ASG-RDS-EC-ES"
    event_pattern = file("${path.module}/policies/events-REDSHIFT-ASG-RDS-EC-ES.json")
    is_enabled    = true
    name          = "divvycloud-root-consumer-${var.license_fingerprint}-REDSHIFT-ASG-RDS-EC-ES"
    tags          = {}
}

resource "aws_cloudwatch_event_rule" "DivvyCloud-EDH-CloudWatch-Consumer-Rule-S3-KMS-IAM" {
    description   = "divvycloud Event Driven Harvesting S3-KMS-IAM"
    event_pattern = file("${path.module}/policies/events-S3-KMS-IAM.json")
    is_enabled    = true
    name          = "divvycloud-root-consumer-${var.license_fingerprint}-S3-KMS-IAM"
    tags          = {}
}

// Consumer CloudWatch rule targets
resource "aws_cloudwatch_event_target" "DivvyCloud-EC2-0-Consumer-Target" {
    arn       = aws_sqs_queue.DivvyCloud-Consumer-SQS.arn
    role_arn  = aws_iam_role.DivvyCloud-Consumer-EventBus-Role.arn
    rule      = aws_cloudwatch_event_rule.DivvyCloud-EDH-CloudWatch-Consumer-Rule-EC2-0.name
    target_id = "default"
}

resource "aws_cloudwatch_event_target" "DivvyCloud-EC2-1-Consumer-Target" {
    arn       = aws_sqs_queue.DivvyCloud-Consumer-SQS.arn
    role_arn  = aws_iam_role.DivvyCloud-Consumer-EventBus-Role.arn
    rule      = aws_cloudwatch_event_rule.DivvyCloud-EDH-CloudWatch-Consumer-Rule-EC2-1.name
    target_id = "default"
}

resource "aws_cloudwatch_event_target" "DivvyCloud-ECR-ECS-R53-CFT-Consumer-Target" {
    arn       = aws_sqs_queue.DivvyCloud-Consumer-SQS.arn
    role_arn  = aws_iam_role.DivvyCloud-Consumer-EventBus-Role.arn
    rule      = aws_cloudwatch_event_rule.DivvyCloud-EDH-CloudWatch-Consumer-Rule-ECR-ECS-R53-CFT.name
    target_id = "default"
}

resource "aws_cloudwatch_event_target" "DivvyCloud-REDSHIFT-ASG-RDS-EC-ES-Consumer-Target" {
    arn       = aws_sqs_queue.DivvyCloud-Consumer-SQS.arn
    role_arn  = aws_iam_role.DivvyCloud-Consumer-EventBus-Role.arn
    rule      = aws_cloudwatch_event_rule.DivvyCloud-EDH-CloudWatch-Consumer-Rule-REDSHIFT-ASG-RDS-EC-ES.name
    target_id = "default"
}

resource "aws_cloudwatch_event_target" "DivvyCloud-S3-KMS-IAM-Consumer-Target" {
    arn       = aws_sqs_queue.DivvyCloud-Consumer-SQS.arn
    role_arn  = aws_iam_role.DivvyCloud-Consumer-EventBus-Role.arn
    rule      = aws_cloudwatch_event_rule.DivvyCloud-EDH-CloudWatch-Consumer-Rule-S3-KMS-IAM.name
    target_id = "default"
}
*/