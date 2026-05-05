FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

RUN apt-get update && apt-get install -y \
    openssh-server sudo vim nano curl wget git \
    net-tools iputils-ping iproute2 \
    python3 python3-pip \
    nginx php-fpm php-cli \
    vsftpd \
    postfix mailutils \
    postgresql-client libpq-dev python3-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/betheroot/pghoney.git /opt/pghoney && \
    pip3 install -r /opt/pghoney/requirements.txt

RUN mkdir -p /var/run/sshd /root/.ssh && chmod 700 /root/.ssh

RUN echo 'root:victim456' | chpasswd

RUN sed -i \
        's/#PermitRootLogin prohibit-password/PermitRootLogin yes/; \
         s/#PasswordAuthentication yes/PasswordAuthentication yes/' \
        /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash postgres  && echo 'postgres:postgres'     | chpasswd && \
    useradd -m -s /bin/bash dbadmin   && echo 'dbadmin:dbadmin123'    | chpasswd && \
    useradd -m -s /bin/bash webuser   && echo 'webuser:web123'        | chpasswd && \
    useradd -m -s /bin/bash ftpuser   && echo 'ftpuser:ftp456'        | chpasswd

COPY nginx-default.conf /etc/nginx/sites-available/default
COPY web/index.php      /var/www/html/index.php
COPY vsftpd.conf        /etc/vsftpd.conf
COPY pghoney-config.json /opt/pghoney/config.json

RUN postconf -e 'myhostname = victim2.honeypot.local' && \
    postconf -e 'mydestination = victim2.honeypot.local, localhost.localdomain, localhost' && \
    postconf -e 'mynetworks = 10.0.0.0/8 127.0.0.0/8' && \
    postconf -e 'inet_interfaces = all' && \
    postconf -e 'smtpd_banner = $myhostname ESMTP PostgreSQL Server'

RUN mkdir -p /var/log/pghoney && \
    mkdir -p /home/ftpuser/ftp && \
    chown ftpuser:ftpuser /home/ftpuser/ftp && \
    echo "Welcome to Victim2 FTP - Database Backups" > /home/ftpuser/ftp/readme.txt && \
    echo "database_backup_2024.sql"                   > /home/ftpuser/ftp/backup_list.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80 21 25 5432

CMD ["/entrypoint.sh"]
