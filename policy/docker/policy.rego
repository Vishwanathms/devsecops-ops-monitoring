package main

# Deny if Dockerfile explicitly uses root user
deny[msg] {
  some i
  lower(trim(input[i].value, " ")) == "root"
  lower(input[i].instruction) == "user"
  msg = "❌ Dockerfile explicitly uses root user"
}

# Deny if Dockerfile explicitly uses root user
deny[msg] {
  some i
  lower(input[i].instruction) == "user"
  re_match("(?i)^root$", trim(input[i].value, " "))
  msg = "❌ Policy Violation: Dockerfile explicitly uses root user"
}

# ❌ Deny if Dockerfile has no USER directive (defaults to root)
deny[msg] {
  not user_exists
  msg = "⚠️ Dockerfile has no USER directive (defaults to root)"
}

# ✅ Complete rule — always returns a value
user_exists = true {
  some i
  lower(input[i].instruction) == "user"
}

user_exists = false {
  not some i
  lower(input[i].instruction) == "user"
}
