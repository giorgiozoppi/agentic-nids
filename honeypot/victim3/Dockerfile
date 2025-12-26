FROM ubuntu:22.04

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
    net-tools \
    iputils-ping \
    iproute2 \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Redis client for testing
RUN apt-get update && apt-get install -y \
    redis-tools \
    && rm -rf /var/lib/apt/lists/*

# Clone and setup Redis Honeypot
RUN git clone https://github.com/cypwnpwnsocute/RedisHoneyPot.git /opt/RedisHoneyPot && \
    cd /opt/RedisHoneyPot && \
    pip3 install -r requirements.txt || pip3 install redis

# Install web server (lighttpd - lightweight)
RUN apt-get update && apt-get install -y \
    lighttpd \
    php-cgi \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh

# Set root password
RUN echo 'root:victim789' | chpasswd

# Configure SSH
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create users with weak passwords
RUN useradd -m -s /bin/bash redis && echo 'redis:redis' | chpasswd && \
    useradd -m -s /bin/bash cache && echo 'cache:cache123' | chpasswd && \
    useradd -m -s /bin/bash webadmin && echo 'webadmin:admin123' | chpasswd

# Configure lighttpd
RUN lighty-enable-mod fastcgi && \
    lighty-enable-mod fastcgi-php

# Create a simple web page
RUN echo '<?php\n\
echo "<h1>Victim Server 3 - Cache Server</h1>";\n\
echo "<p>Server Status: Online</p>";\n\
echo "<p>Redis Honeypot Running on port 6379</p>";\n\
echo "<p>System: " . php_uname() . "</p>";\n\
?>\n\
<div style=\"border: 1px solid #ccc; padding: 10px; margin: 10px 0;\">\n\
<h3>Redis Info</h3>\n\
<p>Host: victim3 (172.20.0.40)</p>\n\
<p>Port: 6379</p>\n\
<p>Protected Mode: Disabled (honeypot)</p>\n\
<p><small>All Redis commands are logged for analysis</small></p>\n\
</div>\n\
<div style=\"background: #fffacd; padding: 10px; margin: 10px 0;\">\n\
<h3>Common Redis Commands</h3>\n\
<pre>\n\
redis-cli -h 172.20.0.40\n\
INFO\n\
KEYS *\n\
GET key\n\
SET key value\n\
</pre>\n\
</div>' > /var/www/html/index.php

# Create logs directory for Redis honeypot
RUN mkdir -p /var/log/redis-honeypot && \
    chmod 777 /var/log/redis-honeypot

# Create startup script
RUN echo '#!/bin/bash\n\
service ssh start\n\
service lighttpd start\n\
cd /opt/RedisHoneyPot && python3 server.py &\n\
echo "==========================================="\n\
echo "  Victim Server 3 Ready (with Redis Honeypot)"\n\
echo "==========================================="\n\
echo "Running Services:"\n\
echo "  - SSH (port 22) - root:victim789"\n\
echo "  - HTTP (port 80) - Lighttpd"\n\
echo "  - Redis Honeypot (port 6379)"\n\
echo ""\n\
echo "Network Info:"\n\
ip addr show eth0 | grep inet\n\
echo ""\n\
echo "User Accounts:"\n\
echo "  - root:victim789"\n\
echo "  - redis:redis"\n\
echo "  - cache:cache123"\n\
echo "  - webadmin:admin123"\n\
echo ""\n\
echo "Redis Honeypot Logs: /var/log/redis-honeypot/"\n\
echo "==========================================="\n\
tail -f /dev/null' > /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 22 80 6379

CMD ["/entrypoint.sh"]
