package docker

# Deny if USER root is explicitly set
deny[msg] {
  some i
  input.Instructions[i].Cmd == "USER"
  lower(input.Instructions[i].Value) == "root"
  msg = "❌ Policy Violation: Dockerfile explicitly runs as root user"
}

# Deny if no USER directive is specified (implicit root)
deny[msg] {
  not user_specified
  msg = "⚠️ Policy Violation: Dockerfile has no USER directive (defaults to root)"
}

# Helper rule to check if a USER directive exists
user_specified {
  some i
  input.Instructions[i].Cmd == "USER"
}
