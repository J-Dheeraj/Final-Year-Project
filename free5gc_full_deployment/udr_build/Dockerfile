# Builds the real, unmodified free5gc/udr binary at a specific commit
# (ARG UDR_COMMIT), for use as the `free5gc-udr` service image in the
# official free5gc-compose stack. Not a synthetic reproduction: this
# clones and compiles the genuine upstream source at the given commit,
# the same commit pinning discipline used for the CVE-2026-40248
# minimal harness (free5gc_runtime_case/).
#
# Base images are pinned by digest, not a floating tag, so this build
# is reproducible months later regardless of what golang:1.26-bookworm
# or debian:bookworm-slim point to by then. Re-pin by running:
#   docker pull golang:1.26-bookworm && docker inspect --format='{{index .RepoDigests 0}}' golang:1.26-bookworm
#   docker pull debian:bookworm-slim  && docker inspect --format='{{index .RepoDigests 0}}' debian:bookworm-slim
FROM golang:1.26-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS builder
ARG UDR_COMMIT
ENV UDR_COMMIT=${UDR_COMMIT}
WORKDIR /src
# UDR_COMMIT is read via printenv, not $UDR_COMMIT/${UDR_COMMIT} textual
# substitution, so a value containing shell metacharacters cannot inject
# into this RUN command - Docker's own ARG/ENV substitution only matches
# that literal text pattern in the Dockerfile source, which this
# deliberately avoids. Validated as a 40-hex-char git SHA, optionally
# with one trailing ^ ("parent of") - the form this project's own
# automation already uses for the pre-fix commit (see
# run_full_deployment_harness.py's VULN_COMMIT = f"{FIX_COMMIT}^").
RUN commit="$(printenv UDR_COMMIT)"; \
    echo "$commit" | grep -Eq '^[0-9a-fA-F]{40}\^?$' \
      || (echo "UDR_COMMIT must be a 40-hex-char git SHA, optionally with one trailing ^, got: $commit" >&2 && exit 1) \
    && git clone https://github.com/free5gc/udr.git . \
    && git checkout "$commit" \
    && go build -o /udr ./cmd/...

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --no-create-home --uid 10001 --shell /usr/sbin/nologin udr
WORKDIR /free5gc
RUN mkdir -p config/ log/ cert/ && chown -R udr:udr /free5gc
COPY --from=builder --chown=udr:udr /udr ./udr
USER udr
ENTRYPOINT ["/usr/bin/tini", "--"]
EXPOSE 8000
