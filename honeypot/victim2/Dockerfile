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

# Install web server (Nginx)
RUN apt-get update && apt-get install -y \
    nginx \
    php-fpm \
    php-cli \
    && rm -rf /var/lib/apt/lists/*

# Install FTP server (vsftpd)
RUN apt-get update && apt-get install -y \
    vsftpd \
    && rm -rf /var/lib/apt/lists/*

# Install SMTP server (Postfix)
RUN apt-get update && apt-get install -y \
    postfix \
    mailutils \
    && rm -rf /var/lib/apt/lists/*

# Install PostgreSQL client (for pghoney)
RUN apt-get update && apt-get install -y \
    postgresql-client \
    libpq-dev \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install pghoney - PostgreSQL honeypot
RUN git clone https://github.com/betheroot/pghoney.git /opt/pghoney && \
    cd /opt/pghoney && \
    pip3 install -r requirements.txt

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh

# Set root password
RUN echo 'root:victim456' | chpasswd

# Configure SSH
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create users with weak passwords
RUN useradd -m -s /bin/bash postgres && echo 'postgres:postgres' | chpasswd && \
    useradd -m -s /bin/bash dbadmin && echo 'dbadmin:dbadmin123' | chpasswd && \
    useradd -m -s /bin/bash webuser && echo 'webuser:web123' | chpasswd && \
    useradd -m -s /bin/bash ftpuser && echo 'ftpuser:ftp456' | chpasswd

# Configure Nginx
RUN echo 'server {\n\
    listen 80 default_server;\n\
    listen [::]:80 default_server;\n\
    root /var/www/html;\n\
    index index.php index.html index.htm;\n\
    server_name victim2;\n\
    location / {\n\
        try_files $uri $uri/ =404;\n\
    }\n\
    location ~ \.php$ {\n\
        include snippets/fastcgi-php.conf;\n\
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;\n\
    }\n\
}' > /etc/nginx/sites-available/default

# Create a simple web page
RUN echo '<?php\n\
echo "<h1>Victim Server 2 - Database Portal</h1>";\n\
echo "<p>Server Status: Online</p>";\n\
echo "<p>PostgreSQL Honeypot Running on port 5432</p>";\n\
echo "<p>System: " . php_uname() . "</p>";\n\
if(isset($_GET["query"])) {\n\
    echo "<div style=\"background: #f0f0f0; padding: 10px; margin: 10px 0;\">";\n\
    echo "<h3>SQL Query Input (Demo)</h3>";\n\
    echo "<pre>" . htmlspecialchars($_GET["query"]) . "</pre>";\n\
    echo "</div>";\n\
}\n\
?>\n\
<form method="GET">\n\
    <textarea name="query" rows="5" cols="50" placeholder="Enter SQL query..."></textarea><br>\n\
    <input type="submit" value="Execute">\n\
</form>\n\
<p><small>Note: This is a honeypot. All interactions are logged.</small></p>' > /var/www/html/index.php

# Configure vsftpd
RUN echo "listen=YES\n\
listen_ipv6=NO\n\
anonymous_enable=NO\n\
local_enable=YES\n\
write_enable=YES\n\
local_umask=022\n\
dirmessage_enable=YES\n\
use_localtime=YES\n\
xferlog_enable=YES\n\
connect_from_port_20=YES\n\
chroot_local_user=YES\n\
allow_writeable_chroot=YES\n\
secure_chroot_dir=/var/run/vsftpd/empty\n\
pam_service_name=vsftpd\n\
ssl_enable=NO" > /etc/vsftpd.conf

# Configure Postfix for basic SMTP
RUN postconf -e 'myhostname = victim2.honeypot.local' && \
    postconf -e 'mydestination = victim2.honeypot.local, localhost.localdomain, localhost' && \
    postconf -e 'mynetworks = 172.20.0.0/24 127.0.0.0/8' && \
    postconf -e 'inet_interfaces = all' && \
    postconf -e 'smtpd_banner = $myhostname ESMTP PostgreSQL Server'

# Configure pghoney
RUN mkdir -p /var/log/pghoney && \
    echo '{\n\
    "host": "0.0.0.0",\n\
    "port": 5432,\n\
    "logfile": "/var/log/pghoney/pghoney.log",\n\
    "database": "honeypot",\n\
    "username": "postgres",\n\
    "password": "postgres",\n\
    "fake_version": "PostgreSQL 12.2"\n\
}' > /opt/pghoney/config.json

# Create FTP directory
RUN mkdir -p /home/ftpuser/ftp && \
    chown ftpuser:ftpuser /home/ftpuser/ftp && \
    echo "Welcome to Victim2 FTP Server - Database Backups" > /home/ftpuser/ftp/readme.txt && \
    echo "database_backup_2024.sql" > /home/ftpuser/ftp/backup_list.txt

# Create startup script
RUN echo '#!/bin/bash\n\
service ssh start\n\
service php8.1-fpm start\n\
service nginx start\n\
service vsftpd start\n\
service postfix start\n\
cd /opt/pghoney && python3 pghoney.py &\n\
echo "==========================================="\n\
echo "  Victim Server 2 Ready (with PGHoney)"\n\
echo "==========================================="\n\
echo "Running Services:"\n\
echo "  - SSH (port 22) - root:victim456"\n\
echo "  - HTTP (port 80) - Nginx"\n\
echo "  - FTP (port 21) - ftpuser:ftp456"\n\
echo "  - SMTP (port 25) - Postfix"\n\
echo "  - PostgreSQL Honeypot (port 5432) - pghoney"\n\
echo ""\n\
echo "Network Info:"\n\
ip addr show eth0 | grep inet\n\
echo ""\n\
echo "User Accounts:"\n\
echo "  - root:victim456"\n\
echo "  - postgres:postgres"\n\
echo "  - dbadmin:dbadmin123"\n\
echo "  - webuser:web123"\n\
echo "  - ftpuser:ftp456"\n\
echo ""\n\
echo "PGHoney Logs: /var/log/pghoney/pghoney.log"\n\
echo "==========================================="\n\
tail -f /dev/null' > /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 22 80 21 25 5432

CMD ["/entrypoint.sh"]
