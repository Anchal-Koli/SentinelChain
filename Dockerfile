# Dockerfile for SentinelChain Containerized Forensic Environment
FROM ubuntu:24.04

# Avoid interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive

# Update system and install prerequisite utilities
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    software-properties-common \
    python3 \
    python3-pip \
    python3-venv \
    tshark \
    suricata \
    git \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Add zeek repository and install zeek
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
    && apt-get update \
    && apt-get install -y zeek-lts || apt-get install -y zeek \
    && rm -rf /var/lib/apt/lists/*

# Set up environment paths for Zeek
ENV PATH="/opt/zeek/bin:${PATH}"

# Install necessary Python libraries for correlation engine
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
RUN pip install --no-cache-dir \
    pandas \
    networkx \
    matplotlib \
    requests \
    google-generativeai

# Set working directory inside container
WORKDIR /workspace

# Default command: sleep to keep container alive for interactive execution
CMD ["sleep", "infinity"]
