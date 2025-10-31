resource "aws_s3_bucket" "bad_bucket" {
  bucket = "public-bucket-demo"
  #acl    = "public-read"
  acl    = "private"
}
