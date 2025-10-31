package main

# Find all USER values no matter how the parser shapes input
users := us {
  us := [val |
    some path, node
    walk(input, [path, node])                 # recursively visit the whole input
    is_object(node)
    lower(object.get(node, "Cmd", "")) == "user"
    vals := object.get(node, "Value", [])
    count(vals) > 0
    val := lower(trim(vals[0], " "))          # normalize " appuser "
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
