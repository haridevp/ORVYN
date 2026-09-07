FROM zaproxy/zap-stable:latest

USER root

# Install Python 3, pip, git, perl dependencies, and utilities
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    perl \
    libnet-ssleay-perl \
    libxml-writer-perl \
    libio-socket-ssl-perl \
    git \
    wget \
    unzip \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Ensure /zap/wrk directory exists with write permissions for ZAP baseline reports
RUN mkdir -p /zap/wrk && chmod 777 /zap/wrk

# Install Nikto
RUN git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

# Install Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip && \
    unzip nuclei_3.2.0_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei_3.2.0_linux_amd64.zip

# Ensure zap-baseline.py is accessible in PATH
ENV PATH="/zap:$PATH"

WORKDIR /app

# Copy only requirements first to leverage Docker layer caching
COPY requirements.txt .

# Setup virtual environment and install python dependencies with retry & timeout protection
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip3 install --no-cache-dir --retries 10 --timeout 60 -r requirements.txt

# Copy source code after dependencies are installed
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]