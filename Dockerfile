FROM python:3.10-slim
WORKDIR /app
COPY python_app/requirements.txt .
RUN pip install -r requirements.txt
COPY python_app/ .
EXPOSE 5000
CMD ["python", "app.py"]
