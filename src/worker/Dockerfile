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
RUN rm -rf /opt/nikto && \
    git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

# Install Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip && \
    unzip -o nuclei_3.2.0_linux_amd64.zip && \
    mv -f nuclei /usr/local/bin/ && \
    rm -f nuclei_3.2.0_linux_amd64.zip

# Ensure zap-baseline.py is accessible in PATH
ENV PATH="/zap:$PATH"

WORKDIR /app

COPY requirements.txt .

# Setup virtual environment and install python dependencies
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

CMD ["celery", "-A", "worker", "worker", "--loglevel=info"]