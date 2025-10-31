package main

# Helper: normalize any value to a lowercased string without using to_string()
normalize(x) = s {
  s := lower(sprintf("%v", [x]))
}

# ---- Case A: "classic map" shape ----
# {
#   "resource": {
#     "aws_s3_bucket": {
#       "bad_bucket": { "acl": "public-read", ... }
#     }
#   }
# }
deny[msg] {
  some name
  acl := input.resource.aws_s3_bucket[name].acl
  normalize(acl) == "public-read"
  msg := sprintf("❌ S3 bucket '%s' should not be publicly accessible", [name])
}

# ---- Case B: HCL2 block with attributes ----
# node = {
#   "type": "aws_s3_bucket",
#   "name": "bad_bucket",
#   "attributes": { "acl": "public-read", ... }
# }
deny[msg] {
  some _path, node
  walk(input, [_path, node])
  is_object(node)
  normalize(object.get(node, "type", "")) == "aws_s3_bucket"

  attrs := object.get(node, "attributes", {})
  acl   := normalize(object.get(attrs, "acl", ""))
  acl == "public-read"

  name := sprintf("%v", [object.get(node, "name", join("_", object.get(node, "labels", [])))])
  msg  := sprintf("❌ S3 bucket '%s' should not be publicly accessible", [name])
}

# ---- Case C: HCL2 block with expressions ----
# node = {
#   "type": "aws_s3_bucket",
#   "name": "bad_bucket",
#   "expressions": { "acl": { "constant_value": "public-read" }, ... }
# }
deny[msg] {
  some _path, node
  walk(input, [_path, node])
  is_object(node)
  normalize(object.get(node, "type", "")) == "aws_s3_bucket"

  exprs    := object.get(node, "expressions", {})
  acl_expr := object.get(exprs, "acl", {})
  acl      := normalize(object.get(acl_expr, "constant_value", ""))
  acl == "public-read"

  name := sprintf("%v", [object.get(node, "name", join("_", object.get(node, "labels", [])))])
  msg  := sprintf("❌ S3 bucket '%s' should not be publicly accessible", [name])
}
