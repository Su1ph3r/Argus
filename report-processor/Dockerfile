FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY process_reports.py .
COPY merge_findings.py .
COPY db_loader.py .
COPY generate_summary.py .
COPY send_notifications.py .
COPY compare_scans.py .

# Create directories
RUN mkdir -p /reports /processed

# Set environment variables
ENV PYTHONUNBUFFERED=1

CMD ["python", "process_reports.py"]
