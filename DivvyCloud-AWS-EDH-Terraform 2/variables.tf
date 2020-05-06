/*
AWS - EDH - Variables
Author: Brendan Elliott
Date:   04/22/20
Ver:    1.1
*/

// Provider Info
provider "aws" {
    profile    = "default"
    region     = var.region
    allowed_account_ids = ["${var.producer_account_id}","${var.consumer_account_id}"]
}

// Account ID of consumer account
variable "consumer_account_id" {
    type    = string
    default = "XXXXXXXXXXXX"
}

// Existing DivvyCloud harvesting role nme to attach EDH (consumer/produer) policy (NOT ARN)
variable "divvycloud_role_name" {
  type      = string
  default   = "DivvyCloud-Standard-Role"
}

// First 8 pairs from DivvyCloud license fingerprint, no colons
// eg 8A:62:80:CC:E2:5F:5D:CF:3B:86:D3:98:1B:7F:08:43:55:9A:40:53
variable "license_fingerprint" {
  type      = string
  default   = "8A6280CCE25F5DCF"
}

variable "organization_id" {
    type = string
    default = "o-6ovjaaxaj3"
}

variable "producer_account_id" {
    type    = string
    default = "YYYYYYYYYYYY"
}

variable "region" {
    type = string
    default = "us-east-1"
}
