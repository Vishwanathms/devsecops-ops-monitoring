package main

# ❌ Deny if Dockerfile explicitly runs as root
deny[msg] {
  instr := input[_][_]                       # flatten stages and instructions
  lower(instr.Cmd) == "user"
  val := lower(trim(instr.Value[0], " "))    # Value is an array; take the first item
  val == "root"
  msg = "❌ Dockerfile explicitly uses root user"
}

# ❌ Deny if Dockerfile has no USER directive (defaults to root)
deny[msg] {
  count([1 | instr := input[_][_]; lower(instr.Cmd) == "user"]) == 0
  msg = "⚠️ Dockerfile has no USER directive (defaults to root)"
}
