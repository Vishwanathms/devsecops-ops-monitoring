package main

# FAIL if USER root is explicitly defined
deny[msg] {
  some i
  input[i].instruction == "user"
  lower(trim(input[i].value)) == "root"
  msg = "❌ Dockerfile explicitly uses root user"
}

# FAIL if no USER directive exists (default root)
deny[msg] {
  not user_defined
  msg = "⚠️ Dockerfile has no USER directive (defaults to root)"
}

user_defined {
  some i
  input[i].instruction == "user"
}
