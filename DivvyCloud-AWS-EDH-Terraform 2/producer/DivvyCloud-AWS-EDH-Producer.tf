/*
AWS - EDH - Producer
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

// Producer IAM
resource "aws_iam_role" "DivvyCloud-Producer-EventBus-Role" {
  name = "divvycloud-eventbus-role"
  path = "/service-role/event-driven-harvest/"

  assume_role_policy = file("${path.module}/policies/eventbus-producer-sts.json")
}

resource "aws_iam_policy" "DivvyCloud-Producer-EventBus-Role-Policy" {
  name        = "divvycloud-eventbus-policy"
  path        = "/service-role/event-driven-harvest/"
  description = "DivvyCloud EDH producer role"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "events:PutEvents"
            ],
            "Resource": [
                "arn:aws:events:*:${var.consumer_account_id}:event-bus/default"
            ],
            "Effect": "Allow"
        }
    ]
}
EOF
}

resource "aws_iam_policy" "DivvyCloud-Producer-Role-Policy" {
  name        = "DivvyCloud-EDH-Producer"
  description = "DivvyCloud EDH Producer Policy"

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
            "Resource": "arn:aws:events:${var.region}:${var.producer_account_id}:rule/divvycloud*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreatePolicyVersion",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRole",
                "iam:PassRole"
            ],
            "Resource": [
                "${aws_iam_policy.DivvyCloud-Producer-EventBus-Role-Policy.arn}",
                "${aws_iam_role.DivvyCloud-Producer-EventBus-Role.arn}"
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

resource "aws_iam_role_policy_attachment" "DivvyCloud-Producer-Role-Attach" {
  role       = var.divvycloud_role_name
  policy_arn = aws_iam_policy.DivvyCloud-Producer-Role-Policy.arn
}

resource "aws_iam_role_policy_attachment" "DivvyCloud-Producer-EventBus-Role-Attach" {
  role       = aws_iam_role.DivvyCloud-Producer-EventBus-Role.name
  policy_arn = aws_iam_policy.DivvyCloud-Producer-EventBus-Role-Policy.arn
}

// Producer CloudTrail S3 bucket
resource "aws_s3_bucket" "DivvyCloud-Producer-CloudTrail-S3" {
  bucket                      = "divvycloud-edh-producer-${var.producer_account_id}"
  force_destroy               = true
  region                      = var.region
  request_payer               = "BucketOwner"
  tags                        = {}

  versioning {
      enabled    = false
      mfa_delete = false
    }
}

resource "aws_s3_bucket_policy" "DivvyCloud-Producer-CloudTrail-S3-Policy" {
  bucket = aws_s3_bucket.DivvyCloud-Producer-CloudTrail-S3.bucket
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
            "Resource": "${aws_s3_bucket.DivvyCloud-Producer-CloudTrail-S3.arn}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "${aws_s3_bucket.DivvyCloud-Producer-CloudTrail-S3.arn}/AWSLogs/${var.producer_account_id}/*",
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


// Producer EDH CloudTrail
resource "aws_cloudtrail" "DivvyCloud-Producer-CloudTrail" {
    depends_on                    = [aws_s3_bucket_policy.DivvyCloud-Producer-CloudTrail-S3-Policy]
    include_global_service_events = true
    is_multi_region_trail         = true
    is_organization_trail         = false
    // Encrypt logs files?
    kms_key_id                    = aws_kms_key.DivvyCloud-Producer-CloudTrail-KMS.arn
    name                          = "DivvyCloud-Producer-CloudTrail-${var.producer_account_id}"
    s3_bucket_name                = aws_s3_bucket.DivvyCloud-Producer-CloudTrail-S3.bucket
    event_selector {
      read_write_type             = "WriteOnly"
      include_management_events   = true
    }
}

resource "aws_kms_alias" "DivvyCloud-Producer-CloudTrail-KMS-Alias" {
  name          = "alias/DivvyCloud-Producer-CloutTrail-KMS-${random_string.DivvyCloud-Random-Short.result}"
  target_key_id = aws_kms_key.DivvyCloud-Producer-CloudTrail-KMS.id
}

resource "aws_kms_key" "DivvyCloud-Producer-CloudTrail-KMS" {
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
                    "arn:aws:iam::${var.producer_account_id}:root"
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
                    "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${var.producer_account_id}:trail/*"
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
                    "kms:CallerAccount": "${var.producer_account_id}"
                },
                "StringLike": {
                    "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${var.producer_account_id}:trail/*"
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
                    "kms:CallerAccount": "${var.producer_account_id}"
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
                    "kms:CallerAccount": "${var.producer_account_id}"
                },
                "StringLike": {
                    "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${var.producer_account_id}:trail/*"
                }
            }
        }
    ]
}
EOF
}