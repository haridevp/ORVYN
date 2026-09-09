FROM zaproxy/zap-stable:latest

USER root

# Install Python 3, pip, git, perl dependencies, and security utilities
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
    curl \
    unzip \
    nmap \
    whatweb \
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

# Ensure /zap/wrk directory exists with write permissions for ZAP baseline reports
RUN mkdir -p /zap/wrk && chmod 777 /zap/wrk

# Install Nikto
RUN rm -rf /opt/nikto && \
    git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

# Install Nuclei and pre-cache community templates
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip && \
    unzip -o nuclei_3.2.0_linux_amd64.zip && \
    mv -f nuclei /usr/local/bin/ && \
    rm -f nuclei_3.2.0_linux_amd64.zip && \
    nuclei -update-templates || true

# Install Ffuf (Fast Web Fuzzer)
RUN wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && \
    tar -xzf ffuf_2.1.0_linux_amd64.tar.gz -C /usr/local/bin/ ffuf && \
    chmod +x /usr/local/bin/ffuf && \
    rm ffuf_2.1.0_linux_amd64.tar.gz

# Pre-seed common discovery wordlists for Ffuf
RUN mkdir -p /usr/share/wordlists/dirb && \
    wget -q https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt -O /usr/share/wordlists/dirb/common.txt || true

# Ensure zap-baseline.py is accessible in PATH
ENV PATH="/zap:$PATH"

WORKDIR /app

# Copy only requirements first to leverage Docker layer caching
COPY requirements.txt .

# Setup virtual environment and install python dependencies (includes sslyze, wapiti3)
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip3 install --no-cache-dir --retries 10 --timeout 60 -r requirements.txt && \
    ln -sf /opt/venv/bin/sslyze /usr/local/bin/sslyze && \
    ln -sf /opt/venv/bin/wapiti /usr/local/bin/wapiti && \
    ln -sf /opt/venv/bin/wapiti3 /usr/local/bin/wapiti3 || true

# Copy source code after dependencies are installed
COPY . .

# Ensure data directory for SQLite database exists
RUN mkdir -p /app/data && chmod 777 /app/data

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]