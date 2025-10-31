package main

# Case A: Classic map shape
deny[msg] {
  some name
  val := lower(to_string(input.resource.aws_s3_bucket[name].acl))
  val == "public-read"
  msg := sprintf("❌ S3 bucket '%s' should not be publicly accessible", [name])
}