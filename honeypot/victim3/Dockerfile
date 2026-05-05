FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

RUN apt-get update && apt-get install -y \
    openssh-server sudo vim nano curl wget git \
    net-tools iputils-ping iproute2 \
    python3 python3-pip \
    redis-tools \
    lighttpd php-cgi \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/cypwnpwnsocute/RedisHoneyPot.git /opt/RedisHoneyPot && \
    pip3 install -r /opt/RedisHoneyPot/requirements.txt 2>/dev/null || pip3 install redis

RUN mkdir -p /var/run/sshd /root/.ssh && chmod 700 /root/.ssh

RUN echo 'root:victim789' | chpasswd

RUN sed -i \
        's/#PermitRootLogin prohibit-password/PermitRootLogin yes/; \
         s/#PasswordAuthentication yes/PasswordAuthentication yes/' \
        /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash redis    && echo 'redis:redis'          | chpasswd && \
    useradd -m -s /bin/bash cache    && echo 'cache:cache123'       | chpasswd && \
    useradd -m -s /bin/bash webadmin && echo 'webadmin:admin123'    | chpasswd

RUN lighty-enable-mod fastcgi fastcgi-php

COPY web/index.php /var/www/html/index.php

RUN mkdir -p /var/log/redis-honeypot && chmod 777 /var/log/redis-honeypot

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80 6379

CMD ["/entrypoint.sh"]
