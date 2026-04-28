# syntax=docker/dockerfile:1.6

# ---------- build stage ----------
FROM golang:1.25-alpine AS build

WORKDIR /src

# Cache deps
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -trimpath -ldflags="-s -w" -o /out/pmt-server ./cmd/server

# ---------- runtime stage ----------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/pmt-server /pmt-server

# Cloud Run sets PORT; we default to 8080 for local runs.
ENV PORT=8080
EXPOSE 8080

USER nonroot:nonroot
ENTRYPOINT ["/pmt-server"]
