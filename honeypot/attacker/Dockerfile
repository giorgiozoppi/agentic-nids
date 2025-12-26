FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Update and install base packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    vim \
    nano \
    curl \
    wget \
    git \
    net-tools \
    iputils-ping \
    iproute2 \
    iptables \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install penetration testing tools
RUN apt-get update && apt-get install -y \
    nmap \
    ettercap-text-only \
    ettercap-common \
    metasploit-framework \
    sqlmap \
    hydra \
    nikto \
    wpscan \
    dirb \
    john \
    hashcat \
    aircrack-ng \
    wireshark-common \
    tshark \
    exploitdb \
    searchsploit \
    netcat-traditional \
    socat \
    masscan \
    gobuster \
    enum4linux \
    smbclient \
    fierce \
    dnsrecon \
    dnsenum \
    whatweb \
    wafw00f \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh

# Set root password
RUN echo 'root:attacker123' | chpasswd

# Configure SSH to allow root login
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config

# Create a non-root user
RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:attacker123' | chpasswd && \
    usermod -aG sudo attacker

# Create workspace
RUN mkdir -p /workspace && chown attacker:attacker /workspace

# Setup Metasploit database
RUN msfdb init || true

# Create a startup script
RUN echo '#!/bin/bash\n\
service ssh start\n\
echo "==========================================="\n\
echo "  Attacker Container Ready"\n\
echo "==========================================="\n\
echo "Installed Tools:"\n\
echo "  - nmap (network scanner)"\n\
echo "  - ettercap (MITM attacks)"\n\
echo "  - metasploit (exploit framework)"\n\
echo "  - sqlmap (SQL injection)"\n\
echo "  - hydra (password cracker)"\n\
echo "  - nikto (web scanner)"\n\
echo "  - and many more..."\n\
echo ""\n\
echo "Network Info:"\n\
ip addr show eth0 | grep inet\n\
echo ""\n\
echo "Targets:"\n\
echo "  - victim1: 172.20.0.20"\n\
echo "  - victim2: 172.20.0.30"\n\
echo "==========================================="\n\
/bin/bash' > /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
