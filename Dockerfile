# --- STAGE 1: Build the binary ---
FROM golang:1.25-bookworm AS builder

# Create and change to the app directory.
WORKDIR /app

# Retrieve application dependencies using go modules.
COPY go.* ./
RUN go mod download

# Copy local code to the container image.
COPY . ./

# Build the binary.
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -v -o server

# --- STAGE 2: Final Runtime Image ---
FROM debian:bookworm-slim

# Define which config file to use (defaults to config.json for non-prod)
ARG CONFIG_FILE=config.json

# Install necessary packages for a production environment.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tzdata \
    procps \
    postgresql-client && \
    rm -rf /var/lib/apt/lists/*

# Set the timezone.
ENV TZ=America/Chicago
RUN echo "${TZ}" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata

# Copy the binary from the builder stage.
COPY --from=builder /app/server /server

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

# docker build --build-arg CONFIG_FILE=config.enc -t myapp:prod .