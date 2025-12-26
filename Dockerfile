# Use Ubuntu 24.04 which includes Python 3.12
FROM ubuntu:24.04

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Create a non-root user for VS Code
RUN useradd -ms /bin/bash vscode

# Install essential utilities and Python 3.12
RUN apt-get update && apt-get install -y \
    git \
    curl \
    make \
    clang-tidy \
    clang-format \
    htop \
    net-tools \
    strace \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libpcap-dev \
    apt-transport-https \
    gnupg \
    ca-certificates \
    python3.12 \
    python3.12-dev \
    python3-pip

# Set Python 3.12 as the default python3
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 && \
    update-alternatives --set python3 /usr/bin/python3.12

RUN curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg && mv bazel-archive-keyring.gpg /usr/share/keyrings
RUN echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list

RUN apt-get update && apt-get install -y bazel && rm -rf /var/lib/apt/lists/*

# Install nDPI
RUN git clone --branch dev https://github.com/ntop/nDPI.git
WORKDIR /nDPI
RUN ./autogen.sh && ./configure && make && make install
#
# # Set working directory

# Switch to non-root user
USER vscode

# RUN curl -LsSf https://astral.sh/uv/install.sh | sh

