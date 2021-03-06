
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
  policy "aws-identify" {
    description = "AWS Identify Section"


    query "APIGateway.1" {
      description = "API Gateway REST and WebSocket API logging should be enabled"
      query =<<EOF
      SELECT a.cq_id,  a.stage_name, a.access_log_settings_destination_arn, a.access_log_settings_format,  b.account_id FROM public.aws_apigatewayv2_api_stages  as a 
      LEFT OUTER JOIN public.aws_apigatewayv2_apis  as b ON a.cq_id = b.cq_id where  a.access_log_settings_destination_arn is NULL
    EOF
    }

    query "APIGateway.2" {
      description = "API Gateway REST API stages should be configured to use SSL certificates for backend authentication"
      query =<<EOF
      SELECT a.cq_id, a.stage_name, a.access_log_settings_destination_arn, a.access_log_settings_format, a.client_certificate_id, b.account_id FROM public.aws_apigatewayv2_api_stages as a LEFT OUTER JOIN public.aws_apigatewayv2_apis  as b ON a.cq_id = b.cq_id where client_certificate_id is NULL
    EOF
    }

    query "APIGateway.3" {
      description = "API Gateway REST API stages should have AWS X-Ray tracing enabled"
      query =<<EOF
      SELECT a.cq_id,  a.stage_name, a.access_log_settings_destination_arn, a.access_log_settings_format, a.client_certificate_id, a.route_settings_data_trace_enabled,  b.account_id FROM public.aws_apigatewayv2_api_stages  as a 
      LEFT OUTER JOIN public.aws_apigatewayv2_apis  as b ON a.cq_id = b.cq_id where route_settings_data_trace_enabled is false
    EOF
    }

    query "AutoScaling.1" {
      description = "Auto Scaling groups associated with a load balancer should use load balancer health checks"
      query =<<EOF
      SELECT cq_id, meta, account_id, region, created_time, image_id, instance_type, launch_configuration_name, associate_public_ip_address, classic_link_vpc_id, classic_link_vpc_security_groups, ebs_optimized, iam_instance_profile, instance_monitoring_enabled, kernel_id, key_name, arn, metadata_options_http_endpoint, metadata_options_http_put_response_hop_limit, metadata_options_http_tokens, placement_tenancy, ramdisk_id, security_groups, spot_price, user_data
	  FROM public.aws_autoscaling_launch_configurations where instance_monitoring_enabled != true
    EOF
    }

    query "CloudFront.2" {
      description = "CloudFront distributions should have origin access identity enabled"
      query =<<EOF
      SELECT a.cq_id, a.account_id, a.arn, b.s3_origin_config_origin_access_identity FROM public.aws_cloudfront_distributions as a LEFT OUTER JOIN public.aws_cloudfront_distribution_origins as b 
      ON a.cq_id = b.cq_id WHERE s3_origin_config_origin_access_identity IS NULL
    EOF
    }

    query "CloudFront.3" {
      description = "CloudFront distributions should require encryption in transit"
      query =<<EOF
      SELECT account_id,  cache_behaviour_field_level_encryption_id FROM public.aws_cloudfront_distributions where cache_behaviour_field_level_encryption_id = '' OR cache_behaviour_field_level_encryption_id is null;
    EOF
    }

    query "CloudFront.4" {
      description = "CloudFront distributions should have origin failover configured"
      query =<<EOF
      SELECT a.cq_id, a.account_id, b.distribution_cq_id, b.failover_criteria_status_codes_items FROM public.aws_cloudfront_distributions as a left outer join public.aws_cloudfront_distribution_origin_groups  as b on a.cq_id = b.distribution_cq_id where failover_criteria_status_codes_items is null
    EOF
    }

    query "CloudFront.5" {
      description = "CloudFront distributions should have logging enabled"
      query =<<EOF
      SELECT cq_id, meta, account_id, arn, cache_behaviour_realtime_log_config_arn FROM public.aws_cloudfront_distributions where cache_behaviour_realtime_log_config_arn is null
    EOF
    }

    query "CloudFront.6" {
      description = "CloudFront distributions should have AWS WAF enabled"
      query =<<EOF
      SELECT account_id, web_acl_id FROM public.aws_cloudfront_distributions where web_acl_id = '' or web_acl_id is null
    EOF
    }

    query "CloudTrail.1" {
      description = "CloudTrail should be enabled and configured with at least one multi-Region trail"
      query =<<EOF
      SELECT  account_id,  is_multi_region_trail FROM public.aws_cloudtrail_trails where is_multi_region_trail is false;
    EOF
    }

    query "CloudTrail.2" {
      description = "CloudTrail should have encryption at rest enabled"
      query =<<EOF
      SELECT cq_id, meta, account_id, log_file_validation_enabled, kms_key_id FROM public.aws_cloudtrail_trails where kms_key_id is null;
    EOF
    }

    query "CloudTrail.4" {
      description = "Ensure CloudTrail log file validation is enabled"
      query =<<EOF
      SELECT cq_id, meta, account_id, log_file_validation_enabled FROM public.aws_cloudtrail_trails where log_file_validation_enabled is false;
    EOF
    }

    query "CloudTrail.5ND" {
      description = "Ensure CloudTrail trails are integrated with Amazon CloudWatch Logs"
      query =<<EOF
      SELECT cq_id, meta, account_id, cloudwatch_logs_log_group_name FROM public.aws_cloudtrail_trails where cloudwatch_logs_log_group_name is null or cloudwatch_logs_log_group_name = '';
    EOF
    }

   }
}