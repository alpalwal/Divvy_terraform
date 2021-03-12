// Provider Info
provider "aws" {
    profile    = "default"
    region     =  var.region
}

variable "region" {
    type = string
    default = "us-east-1"
}

// What account is DivvyCloud running in?
variable "trusted_account_id" {
    type    = string
    default = "625820357955"
}

// IAM
// Create DivvyCloud standard role
resource "aws_iam_role" "DivvyCloud-Standard-Role" {
  name = "DivvyCloud-Standard-Role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${var.trusted_account_id}:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
EOF
}

// Create standard RO policy pt 1
resource "aws_iam_policy" "DivvyCloud-Standard-Role-Policy" {
  name        = "DivvyCloud-Standard-Policy"
  description = "DivvyCloud Standard RO Policy Pt 1"

  policy = file("${path.module}/divvycloud-standard1.json")

}

// Create standard RO policy pt 2
resource "aws_iam_policy" "DivvyCloud-Standard-Role-Policy2" {
  name        = "DivvyCloud-Standard-Policy2"
  description = "DivvyCloud Standard RO Policy Pt 2"

  policy = file("${path.module}/divvycloud-standard2.json")
}

// Create standard RO policy pt 3
resource "aws_iam_policy" "DivvyCloud-Standard-Role-Policy3" {
  name        = "DivvyCloud-Standard-Policy3"
  description = "DivvyCloud Standard RO Policy Pt 3"

  policy = file("${path.module}/divvycloud-standard3.json")
}

// Create EDH Consumer policy
resource "aws_iam_policy" "DivvyCloud-EDH-Consumer-Policy" {
  name        = "DivvyCloud-EDH-Consumer-Policy"
  description = "DivvyCloud EDH Consumer Policy"

  policy = file("${path.module}/EDHConsumerPolicy.json")
}

// Attach DivvyCloud standard policies
resource "aws_iam_role_policy_attachment" "DivvyCloud-Standard-Role-Attach" {
  role       = aws_iam_role.DivvyCloud-Standard-Role.name
  policy_arn = aws_iam_policy.DivvyCloud-Standard-Role-Policy.arn
}

resource "aws_iam_role_policy_attachment" "DivvyCloud-Standard-Role-Attach2" {
  role       = aws_iam_role.DivvyCloud-Standard-Role.name
  policy_arn = aws_iam_policy.DivvyCloud-Standard-Role-Policy2.arn
}

resource "aws_iam_role_policy_attachment" "DivvyCloud-Standard-Role-Attach3" {
  role       = aws_iam_role.DivvyCloud-Standard-Role.name
  policy_arn = aws_iam_policy.DivvyCloud-Standard-Role-Policy3.arn
}

resource "aws_iam_role_policy_attachment" "DivvyCloud-EDH-Consumer-Attach" {
  role       = aws_iam_role.DivvyCloud-Standard-Role.name
  policy_arn = aws_iam_policy.DivvyCloud-EDH-Consumer-Policy.arn
}
