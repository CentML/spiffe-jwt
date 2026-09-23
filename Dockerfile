# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Set default go_version to 1.26.7 (must satisfy the `go` directive in go.mod;
# the golang images set GOTOOLCHAIN=local, so Go will not auto-fetch a newer one)
ARG go_version=1.26.7

# Build the spiffe-helper binary
FROM --platform=$BUILDPLATFORM golang:${go_version}-alpine AS base
WORKDIR /workspace

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Cache dependencies before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the Go source
COPY main.go main.go

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${BUILDPLATFORM} go build -a -o spiffe-jwt ./main.go

# Third-party source for the notices in THIRD-PARTY.txt: vendor the exact module set
# that was just compiled and pack it (see /usr/share/oss-source in the final stage)
RUN go mod vendor && tar -czf /workspace/third-party-src.tar.gz -C /workspace vendor

# OSRB-approved base; CGO_ENABLED=0 binary needs no libc. Runs as non-root uid 1000.
FROM nvcr.io/nvidia/distroless/static:v4.0.0
WORKDIR /

# Install binary
COPY --from=base /workspace/spiffe-jwt .

# Third-party notices and the corresponding source (license compliance; MPL-2.0 §3.2)
COPY THIRD-PARTY.txt /THIRD-PARTY.txt
COPY --from=base /workspace/third-party-src.tar.gz /usr/share/oss-source/third-party-src.tar.gz

# tini dropped: it reaped zombies (this binary spawns none) and worked around
# PID 1 ignoring SIGTERM (the Go runtime installs its own handler).
ENTRYPOINT ["/spiffe-jwt"]
