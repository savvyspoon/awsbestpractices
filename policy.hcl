
policy "cis-v1.20" {
  description = "AWS CIS V1.20 Policy"
  configuration {
    provider "aws" {
      version = ">= 0.5.0"
    }
  }

  policy "aws-cis-section-1" {
    description = "AWS CIS Section 1"

    query "1.1" {
      description = "AWS CIS 1.1 Avoid the use of 'root' account. Show used in last 30 days (Scored)"
      query =<<EOF
      SELECT account_id, password_last_used, user_name FROM aws_iam_users
      WHERE user_name = '<root_account>' AND password_last_used > (now() - '30 days'::interval)
    EOF
    }
  }
}