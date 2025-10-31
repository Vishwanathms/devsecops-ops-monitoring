FROM python:3.10-slim
WORKDIR /app
COPY python_app/requirements.txt .
RUN pip install -r requirements.txt
# ✅ Create a non-root user
RUN adduser --disabled-password appuser
USER appuser
COPY python_app/ .
EXPOSE 5000
CMD ["python", "app.py"]
