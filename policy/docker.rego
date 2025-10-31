package docker

deny[msg] {
  input.Instructions[i].Cmd == "USER"
  input.Instructions[i].Value == "root"
  msg = "❌ Policy Violation: Dockerfile runs as root user"
}
