FROM python:3.9-slim

LABEL maintainer="Security Team"
LABEL description="CloudMapper for AWS infrastructure visualization"

WORKDIR /opt/cloudmapper

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    jq \
    autoconf \
    automake \
    libtool \
    python3-tk \
    awscli \
    && rm -rf /var/lib/apt/lists/*

# Clone CloudMapper
RUN git clone https://github.com/duo-labs/cloudmapper.git . \
    && pip install --no-cache-dir -r requirements.txt

# Create config directory
RUN mkdir -p /root/.aws /reports

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
