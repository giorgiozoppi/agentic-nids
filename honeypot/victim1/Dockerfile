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
    && rm -rf /var/lib/apt/lists/*

# Install web server (Apache)
RUN apt-get update && apt-get install -y \
    apache2 \
    php \
    libapache2-mod-php \
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

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh

# Set root password
RUN echo 'root:victim123' | chpasswd

# Configure SSH
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create users with weak passwords
RUN useradd -m -s /bin/bash admin && echo 'admin:admin' | chpasswd && \
    useradd -m -s /bin/bash webmaster && echo 'webmaster:password123' | chpasswd && \
    useradd -m -s /bin/bash ftpuser && echo 'ftpuser:ftp123' | chpasswd && \
    useradd -m -s /bin/bash mailuser && echo 'mailuser:mail123' | chpasswd

# Configure Apache
RUN echo "ServerName victim1" >> /etc/apache2/apache2.conf && \
    a2enmod php8.1 || a2enmod php

# Create a simple vulnerable web page
RUN echo '<?php\n\
echo "<h1>Victim Server 1 - Web Portal</h1>";\n\
echo "<p>Server Status: Online</p>";\n\
echo "<p>System: " . php_uname() . "</p>";\n\
if(isset($_GET["cmd"])) {\n\
    echo "<pre>";\n\
    system($_GET["cmd"]);\n\
    echo "</pre>";\n\
}\n\
?>\n\
<form method="GET">\n\
    <input type="text" name="cmd" placeholder="Enter command">\n\
    <input type="submit" value="Execute">\n\
</form>' > /var/www/html/index.php

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
RUN postconf -e 'myhostname = victim1.honeypot.local' && \
    postconf -e 'mydestination = victim1.honeypot.local, localhost.localdomain, localhost' && \
    postconf -e 'mynetworks = 172.20.0.0/24 127.0.0.0/8' && \
    postconf -e 'inet_interfaces = all' && \
    postconf -e 'smtpd_banner = $myhostname ESMTP'

# Create FTP directory
RUN mkdir -p /home/ftpuser/ftp && \
    chown ftpuser:ftpuser /home/ftpuser/ftp && \
    echo "Welcome to Victim1 FTP Server" > /home/ftpuser/ftp/welcome.txt

# Create startup script
RUN echo '#!/bin/bash\n\
service ssh start\n\
service apache2 start\n\
service vsftpd start\n\
service postfix start\n\
echo "==========================================="\n\
echo "  Victim Server 1 Ready"\n\
echo "==========================================="\n\
echo "Running Services:"\n\
echo "  - SSH (port 22) - root:victim123"\n\
echo "  - HTTP (port 80) - Apache"\n\
echo "  - FTP (port 21) - ftpuser:ftp123"\n\
echo "  - SMTP (port 25) - Postfix"\n\
echo ""\n\
echo "Network Info:"\n\
ip addr show eth0 | grep inet\n\
echo ""\n\
echo "User Accounts:"\n\
echo "  - root:victim123"\n\
echo "  - admin:admin"\n\
echo "  - webmaster:password123"\n\
echo "  - ftpuser:ftp123"\n\
echo "  - mailuser:mail123"\n\
echo "==========================================="\n\
tail -f /dev/null' > /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 22 80 21 25

CMD ["/entrypoint.sh"]
