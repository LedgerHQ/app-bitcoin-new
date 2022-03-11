# An image derived from ledgerhq/speculos but also containing the bitcoin-core binaries

FROM ghcr.io/ledgerhq/speculos:latest

# install curl
RUN apt update -y && apt install -y curl

# download bitcoin-core and decompress it to /bitcoin
RUN curl -o /tmp/bitcoin.tar.gz https://bitcoin.org/bin/bitcoin-core-22.0/bitcoin-22.0-x86_64-linux-gnu.tar.gz && \
    tar -xf /tmp/bitcoin.tar.gz -C / && \
    mv /bitcoin-22.0 /bitcoin

# Add bitcoin binaries to path
ENV PATH=/bitcoin/bin:$PATH
