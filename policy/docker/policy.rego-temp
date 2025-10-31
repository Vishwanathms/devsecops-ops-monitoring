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

# ❌ Deny if Dockerfile explicitly runs as root
deny[msg] {
  some i
  lower(input[0][i].Cmd) == "user"
  val := lower(trim(input[0][i].Value[0], " "))
  val == "root"
  msg = "❌ Dockerfile explicitly uses root user"
}

# ❌ Deny if Dockerfile has no USER directive (defaults to root)
#deny[msg] {
#  count([i | lower(input[0][i].Cmd) == "user"]) == 0
#  msg = "⚠️ Dockerfile has no USER directive (defaults to root)"
#}

# ❌ Deny if Dockerfile has no USER directive (defaults to root)
deny[msg] {
  user_count := count([x | some instr; instr := input[_][_]; lower(instr.Cmd) == "user"])
  user_count == 0
  msg = "⚠️ Dockerfile has no USER directive (defaults to root)"
}

# ✅ Complete rule — always returns a value
user_exists = true {
  some i
  lower(input[0][i].Cmd) == "user"
}


