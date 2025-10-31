package main

# Deny if Dockerfile explicitly uses root user
deny[msg] {
  some i
  input[i].instruction == "user"
  lower(trim(input[i].value, " ")) == "root"
  msg = "❌ Dockerfile explicitly uses root user"
}

# Deny if no USER directive exists (default = root)
deny[msg] {
  not user_defined
  msg = "⚠️ Dockerfile has no USER directive (defaults to root)"
}

# Helper: check if a USER directive exists
user_defined {
  some i
  input[i].instruction == "user"
}
