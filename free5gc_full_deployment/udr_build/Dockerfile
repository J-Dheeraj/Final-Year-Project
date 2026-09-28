# Builds the real, unmodified free5gc/udr binary at a specific commit
# (ARG UDR_COMMIT), for use as the `free5gc-udr` service image in the
# official free5gc-compose stack. Not a synthetic reproduction: this
# clones and compiles the genuine upstream source at the given commit,
# the same commit pinning discipline used for the CVE-2026-40248
# minimal harness (free5gc_runtime_case/).
FROM golang:1.26-bookworm AS builder
ARG UDR_COMMIT
WORKDIR /src
RUN git clone https://github.com/free5gc/udr.git . \
    && git checkout ${UDR_COMMIT} \
    && go build -o /udr ./cmd/...

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /free5gc
RUN mkdir -p config/ log/ cert/
COPY --from=builder /udr ./udr
ENTRYPOINT ["/usr/bin/tini", "--"]
EXPOSE 8000
