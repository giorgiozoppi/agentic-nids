FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

RUN apt-get update && apt-get install -y \
    openssh-server sudo vim nano curl wget \
    net-tools iputils-ping iproute2 \
    apache2 php libapache2-mod-php \
    vsftpd \
    postfix mailutils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /root/.ssh && chmod 700 /root/.ssh

RUN echo 'root:victim123' | chpasswd

RUN sed -i \
        's/#PermitRootLogin prohibit-password/PermitRootLogin yes/; \
         s/#PasswordAuthentication yes/PasswordAuthentication yes/' \
        /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash admin       && echo 'admin:admin'               | chpasswd && \
    useradd -m -s /bin/bash webmaster   && echo 'webmaster:password123'     | chpasswd && \
    useradd -m -s /bin/bash ftpuser     && echo 'ftpuser:ftp123'            | chpasswd && \
    useradd -m -s /bin/bash mailuser    && echo 'mailuser:mail123'          | chpasswd

RUN echo "ServerName victim1" >> /etc/apache2/apache2.conf && \
    a2enmod php8.1 2>/dev/null || a2enmod php

COPY web/index.php /var/www/html/index.php
COPY vsftpd.conf   /etc/vsftpd.conf

RUN postconf -e 'myhostname = victim1.honeypot.local' && \
    postconf -e 'mydestination = victim1.honeypot.local, localhost.localdomain, localhost' && \
    postconf -e 'mynetworks = 10.0.0.0/8 127.0.0.0/8' && \
    postconf -e 'inet_interfaces = all' && \
    postconf -e 'smtpd_banner = $myhostname ESMTP'

RUN mkdir -p /home/ftpuser/ftp && \
    chown ftpuser:ftpuser /home/ftpuser/ftp && \
    echo "Welcome to Victim1 FTP Server" > /home/ftpuser/ftp/welcome.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80 21 25

CMD ["/entrypoint.sh"]
