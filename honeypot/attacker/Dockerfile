FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

RUN apt-get update && apt-get install -y \
    openssh-server sudo vim nano curl wget git \
    net-tools iputils-ping iproute2 iptables tcpdump \
    nmap ettercap-text-only ettercap-common \
    metasploit-framework sqlmap hydra nikto wpscan \
    dirb john hashcat aircrack-ng wireshark-common tshark \
    exploitdb netcat-traditional socat masscan gobuster \
    enum4linux smbclient fierce dnsrecon dnsenum \
    whatweb wafw00f \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /root/.ssh && chmod 700 /root/.ssh

RUN echo 'root:attacker123' | chpasswd

RUN sed -i \
        's/#PermitRootLogin prohibit-password/PermitRootLogin yes/; \
         s/#PasswordAuthentication yes/PasswordAuthentication yes/' \
        /etc/ssh/sshd_config && \
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash attacker && \
    echo 'attacker:attacker123' | chpasswd && \
    usermod -aG sudo attacker && \
    mkdir -p /workspace && chown attacker:attacker /workspace

RUN msfdb init || true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
