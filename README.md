# Policy as Code + Trivy Jenkins Demo

This repository demonstrates integrating **Policy-as-Code (OPA/Conftest)** and **Trivy** into a Jenkins pipeline for a Python app.

## Folder Structure

```
python-pac-demo/
├── app.py
├── requirements.txt
├── Dockerfile
├── terraform/
│   └── main.tf
├── policy/
│   ├── docker.rego
│   └── terraform.rego
├── Jenkinsfile
└── README.md
```

## Usage

1. Push to GitHub or Azure Repos.
2. Configure Jenkins pipeline (Multibranch or SCM).
3. Run the build — it will:
   - Build Docker image
   - Run Trivy scan
   - Run Policy checks (OPA/Conftest)
   - Build image if all checks pass
