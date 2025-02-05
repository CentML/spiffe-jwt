# Set default go_version to 1.23
ARG go_version=1.23

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

FROM alpine:latest
WORKDIR /

# Install binary
COPY --from=base /workspace/spiffe-jwt .

USER 65532:65532

ENTRYPOINT ["/spiffe-jwt"]
