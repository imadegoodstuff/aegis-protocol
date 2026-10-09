# Bitcoin Inquisition signet node + broadcast relay for the Aegis Bitcoin account.
# One container, two processes: bitcoind (signet, pruned) and server.mjs.
# The node needs a persistent volume at /data (≈ 2 GB pruned) and an initial sync.

FROM node:22-bookworm-slim

ARG INQ_VERSION=29.4-inq
ARG INQ_SHA256=7ad3cb745575f7c21916cf3c294a95f59e11e5bf6e37c4a47b92697cf4723e22

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL -o /tmp/inq.tar.gz "https://github.com/bitcoin-inquisition/bitcoin/releases/download/v${INQ_VERSION}/bitcoin-${INQ_VERSION}-x86_64-linux-gnu.tar.gz" \
 && echo "${INQ_SHA256}  /tmp/inq.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/inq.tar.gz -C /opt && rm /tmp/inq.tar.gz \
 && ln -s /opt/bitcoin-${INQ_VERSION}/bin/bitcoind /usr/local/bin/bitcoind \
 && ln -s /opt/bitcoin-${INQ_VERSION}/bin/bitcoin-cli /usr/local/bin/bitcoin-cli \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /relay
COPY server.mjs start.sh ./
RUN chmod +x start.sh

ENV PORT=8080 \
    BITCOIN_RPC_URL=http://127.0.0.1:38332 \
    BITCOIN_RPC_USER=relay \
    ALLOW_ORIGIN=*

VOLUME /data
EXPOSE 8080
CMD ["./start.sh"]
