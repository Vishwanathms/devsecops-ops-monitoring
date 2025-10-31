package main

# Collect all USER values from the parsed Dockerfile, supporting both shapes:
#  A) 2-D array: input[stage][index] -> { Cmd, Value[] }
#  B) Object:    input.Commands[]    -> { Cmd, Value[] }

users = us {
  us := [val |
    stage := input[_]
    instr := stage[_]
    lower(instr.Cmd) == "user"
    val := lower(trim(instr.Value[0], " "))
  ]
} else = us {
  us := [val |
    cmd := input.Commands[_]
    lower(cmd.Cmd) == "user"
    val := lower(trim(cmd.Value[0], " "))
  ]
}

# ❌ Deny if any USER is root
deny[msg] {
  users[_] == "root"
  msg = "❌ Dockerfile explicitly uses root user"
}

# ❌ Deny if no USER directive exists (defaults to root)
deny[msg] {
  count(users) == 0
  msg = "⚠️ Dockerfile has no USER directive (defaults to root)"
}
