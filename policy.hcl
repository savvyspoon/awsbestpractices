
policy "ABP-v1.00" {
  description = "AWS Best Practices V1"
  configuration {
    provider "aws" {
      version = ">= 0.5.0"
    }
  }

  policy "aws-protect" {
    description = "AWS Protect Section"

    query "ACM.1" {
      description = "Imported ACM certificates should be renewed after a specified time period"
      query =<<EOF
      SELECT cq_id, meta, account_id, region, id, created_date, description, expiration_date, pem_encoded_certificate, tags
	  FROM public.aws_apigateway_client_certificates where expiration_date < current_date - integer '30'
    EOF
    }
  }
}