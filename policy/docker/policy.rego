package main

# Collect all USER values from the parsed Dockerfile, regardless of input shape

# Shape A: input is a 2-D array (e.g., [[{Cmd,Value}, ...]])
users = us {
  us := [ val |
    instr := input[_][_]
    lower(instr.Cmd) == "user"
    val := lower(trim(instr.Value[0], " "))
  ]
} else = us {
  # Shape B: input is {Commands: [{Cmd,Value}, ...]}
  us := [ val |
    cmd := input.Commands[_]
    lower(cmd.Cmd) == "user"
    val := lower(trim(cmd.Value[0], " "))
  ]
}

# ❌ Deny if any USER is root
deny[msg] {
  some v
  v := users[_]
  v == "root"
  msg = "❌ Dockerfile explicitly uses root user"
}

# ❌ Deny if no USER directive exists (defaults to root)
deny[msg] {
  count(users) == 0
  msg = "⚠️ Dockerfile has no USER directive (defaults to root)"
}
