# Use the official Golang image to create a build artifact.
# This is based on Debian and sets the GOPATH to /go.
# https://hub.docker.com/_/golang
FROM golang:1.25-bookworm as builder

# Create and change to the app directory.
WORKDIR /app

# Retrieve application dependencies using go modules.
# Allows container builds to reuse downloaded dependencies.
COPY go.* ./
RUN go mod download

# Copy local code to the container image.
COPY . ./

# Build the binary.
# -mod=readonly ensures immutable go.mod and go.sum in container builds.
RUN CGO_ENABLED=0 GOOS=linux go build -mod=readonly -v -o server

# Use a lean Debian image for the production container.
# https://hub.docker.com/_/debian/
FROM debian:bookworm-slim

# Install necessary packages for a production environment.
# curl and ca-certificates are common for network communication.
# tzdata is needed for timezone configuration.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tzdata \
    procps postgresql-client && rm -rf /var/lib/apt/lists/*

# Set the timezone.
ENV TZ=America/Chicago
RUN echo "${TZ}" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata

# Copy the binary to the production image from the builder stage.
COPY --from=builder /app/server /server

# Copy static assets and configuration.
COPY static /static
COPY kb /kb
COPY data/config.json /config.json
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose the application port
EXPOSE 8080

# Run the entrypoint script on container startup.
ENTRYPOINT ["/entrypoint.sh"]