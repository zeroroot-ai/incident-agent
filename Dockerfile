# Stage 1: build — compiles the agent binary with CGO disabled.
FROM ghcr.io/zeroroot-ai/mirror/golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

# The builder image carries exactly the Go that go.mod names, and the org
# guard (check-go-toolchain.sh, .github#22) fails a PR where they differ.
# GOTOOLCHAIN=local makes a mismatch fail the build instead of downloading a
# toolchain, so the pinned base is the toolchain that built the binary.
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}

# VERSION is stamped into the binary so a running container reports the
# release it was built from. Without it every image reports "dev", which is
# indistinguishable from a local build in the console and in the registry.
ARG VERSION=dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION}" -o /out/incident-agent .

# Stage 2: runtime — distroless, non-root.
#
# static-debian13, not static-debian12. The binary is static and reads nothing
# from the Debian userland, so the only Debian packages in the image are
# ca-certificates, tzdata, base-files and netbase, and the base is chosen by
# which of those is patched. DLA-4792-1 (cve-triage#31) fixes tzdata in
# 2026c-0+deb12u1, and every static-debian12:nonroot build still ships
# 2026b-0+deb12u1 (measured 2026-10-02 on the newest index, sha256:52dcfbab).
# static-debian13:nonroot ships 2026c-0+deb13u1. Move the digest here when a
# scanner names a package in this image; never dismiss the alert.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS runtime

# The binary sits at a stable, documented path because setec does NOT consult
# the image ENTRYPOINT — a sandboxed catalog manifest names the command
# explicitly (`command: /incident-agent`). Moving this path silently breaks every
# dispatch, so it is part of the contract, not an implementation detail.
COPY --from=builder /out/incident-agent /incident-agent

# No EXPOSE and no component.yaml: this agent is dispatched, not enrolled
# (ADR-0116). It is launched per mission run, serves no port, registers with
# nothing, and exits when its pass is done.

# The license text travels with the distribution. Apache-2.0 §4(a) and MIT
# both require the notice to reach every recipient, and a published image is
# a distribution. /licenses is the OCI convention. COPY needs no shell, so it
# works on this distroless base. Last in the stage so a change here rebuilds
# nothing else.
COPY LICENSE /licenses/LICENSE

ENTRYPOINT ["/incident-agent"]
