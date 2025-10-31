package terraform

deny[msg] {
  input.resource.aws_s3_bucket[_].acl == "public-read"
  msg = "❌ S3 bucket should not be publicly accessible"
}
