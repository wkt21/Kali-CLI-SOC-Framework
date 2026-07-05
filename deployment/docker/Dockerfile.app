FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir uvicorn fastapi pydantic
EXPOSE 8000
CMD ["uvicorn", "ops.ingest.server:app", "--host", "0.0.0.0", "--port", "8000"]
