FROM python:3.11-slim

LABEL maintainer="phantom"
LABEL description="Phantom - LLM Red Teaming & Jailbreak Testing Platform"

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

EXPOSE 8666

CMD ["python", "-m", "flask", "--app", "backend.app", "run", "--host", "0.0.0.0", "--port", "8666"]
