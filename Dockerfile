# --- STAGE 1: Build the application binary ---
FROM golang:1.25.3-bookworm AS builder

# Create and change to the app directory.
WORKDIR /app

# Retrieve application dependencies using go modules.
COPY go.* ./
RUN go mod download

# Copy local code to the container image.
COPY . ./

# Build the binary.
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -v -o server

# --- STAGE 2: Extract up-to-date OSV-Scanner ---
FROM ghcr.io/google/osv-scanner:v1.9.2 AS osv-bin

# --- STAGE 3: Final Runtime Image ---
FROM debian:bookworm-20260224-slim

# Define which config file to use (defaults to config.json for non-prod)
ARG CONFIG_FILE=config.json

# Install necessary packages and run an upgrade to eliminate base layer CVEs.
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    tzdata \
    procps \
    postgresql-client && \
    rm -rf /var/lib/apt/lists/*

# Set the timezone.
ENV TZ=America/Chicago
RUN echo "${TZ}" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata

# Copy the server binary from the builder stage.
COPY --from=builder /app/server /server

# Copy the official OSV-Scanner binary into the system PATH
COPY --from=osv-bin /osv-scanner /usr/local/bin/osv-scanner

# Copy static assets and documentation.
COPY static /static
COPY kb /kb

COPY data/${CONFIG_FILE} /${CONFIG_FILE}

# Setup the entrypoint.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose the application port.
EXPOSE 8080

# Run the entrypoint script on container startup.
ENTRYPOINT ["/entrypoint.sh"]