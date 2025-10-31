package main

# -------- helpers (compatible with older OPA) --------

# normalize any value to a lowercased string
normalize(x) = s {
  s := lower(sprintf("%v", [x]))
}

# pick a readable resource name from HCL2 block node
bucket_name(node) = n {
  # prefer explicit "name"
  n := sprintf("%v", [object.get(node, "name", "")])
  n != ""
}
bucket_name(node) = n {
  # otherwise first label if present
  ls := object.get(node, "labels", [])
  count(ls) > 0
  n := sprintf("%v", [ls[0]])
}
bucket_name(node) = "unknown" {
  true
}

# -------- DENY rules --------

# Case A: classic map shape
# input.resource.aws_s3_bucket.bad_bucket.acl == "public-read"
deny[msg] {
  some name
  acl := input.resource.aws_s3_bucket[name].acl
  normalize(acl) == "public-read"
  msg := sprintf("❌ S3 bucket '%s' should not be publicly accessible (acl=public-read)", [name])
}

# Case B: HCL2 block with attributes.acl
# node = { type:"aws_s3_bucket", name:"...", attributes:{ acl:"public-read" } }
deny[msg] {
  some _p, node
  walk(input, [_p, node])
  is_object(node)
  normalize(object.get(node, "type", "")) == "aws_s3_bucket"

  attrs := object.get(node, "attributes", {})
  acl   := normalize(object.get(attrs, "acl", ""))
  acl == "public-read"

  name := bucket_name(node)
  msg  := sprintf("❌ S3 bucket '%s' should not be publicly accessible (acl=public-read)", [name])
}

# Case C: HCL2 block with expressions.acl.constant_value
# node = { type:"aws_s3_bucket", name:"...", expressions:{ acl:{ constant_value:"public-read" } } }
deny[msg] {
  some _p, node
  walk(input, [_p, node])
  is_object(node)
  normalize(object.get(node, "type", "")) == "aws_s3_bucket"

  exprs    := object.get(node, "expressions", {})
  acl_expr := object.get(exprs, "acl", {})
  acl      := normalize(object.get(acl_expr, "constant_value", ""))
  acl == "public-read"

  name := bucket_name(node)
  msg  := sprintf("❌ S3 bucket '%s' should not be publicly accessible (acl=public-read)", [name])
}
