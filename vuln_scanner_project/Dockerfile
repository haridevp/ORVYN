# ==========================================
# STAGE 1: NUCLEI
# ==========================================
FROM projectdiscovery/nuclei:v3.11.1 AS nuclei


# ==========================================
# STAGE 2: MAIN APPLICATION
# ==========================================
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV ZAP_VERSION=2.17.0


# ==========================================
# INSTALL SYSTEM DEPENDENCIES
# ==========================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    nmap \
    perl \
    libnet-ssleay-perl \
    libxml-writer-perl \
    libio-socket-ssl-perl \
    ruby \
    ruby-dev \
    build-essential \
    cmake \
    libyaml-dev \
    zlib1g-dev \
    libssl-dev \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/*


# ==========================================
# COPY NUCLEI BINARY
# ==========================================
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei


# ==========================================
# INSTALL NIKTO
# ==========================================
RUN git clone --depth 1 \
    https://github.com/sullo/nikto.git \
    /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl \
    /usr/local/bin/nikto


# ==========================================
# INSTALL WHATWEB
# ==========================================
RUN git clone --depth 1 \
    https://github.com/urbanadventurer/WhatWeb.git \
    /opt/whatweb && \
    cd /opt/whatweb && \
    gem install bundler --no-document && \
    bundle config set without 'development test' && \
    bundle install && \
    ln -s /opt/whatweb/whatweb \
    /usr/local/bin/whatweb


# ==========================================
# INSTALL SSLScan 2.1.4
# ==========================================
RUN git clone \
    --branch 2.1.4 \
    --depth 1 \
    https://github.com/rbsec/sslscan.git \
    /opt/sslscan && \
    cd /opt/sslscan && \
    make static && \
    cp sslscan /usr/local/bin/sslscan && \
    rm -rf /opt/sslscan


# ==========================================
# INSTALL OWASP ZAP
# ==========================================
RUN wget -qO /tmp/zap.tar.gz \
    https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz && \
    tar -xzf /tmp/zap.tar.gz -C /opt && \
    rm /tmp/zap.tar.gz && \
    ln -s /opt/ZAP_${ZAP_VERSION}/zap.sh \
    /usr/local/bin/zaproxy


# ==========================================
# DOWNLOAD NUCLEI TEMPLATES
# ==========================================
RUN nuclei -update-templates


# ==========================================
# APPLICATION
# ==========================================
WORKDIR /app

COPY requirements.txt .


# ==========================================
# INSTALL PYTHON TOOLS
# ==========================================
RUN pip install --no-cache-dir \
    wapiti3==3.2.10 \
    sslyze && \
    pip install --no-cache-dir -r requirements.txt


# ==========================================
# COPY APPLICATION FILES
# ==========================================
COPY . .


# ==========================================
# ENTRYPOINT
# ==========================================
ENTRYPOINT ["python3", "scanner_engine_2.py"]