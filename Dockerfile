# Start with the Rust base image
FROM rust:1.80 as builder

# Set the working directory
WORKDIR /usr/src/cert-manager-plesk-webhook

# Copy the Cargo workspace configuration files
COPY . .

# Build the application
RUN cargo build --release

# Final stage: Use a slim image for the running container
FROM debian:bookworm-slim
WORKDIR /usr/local/bin

# Install openssl and update certificates
RUN apt-get update && \
    apt-get install -y openssl ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/cert-manager-plesk-webhook/target/release/cert-manager-plesk-webhook .

# Define a volume for the external configuration file
VOLUME /usr/local/bin/config

# Define the command to run the executable
CMD ["./cert-manager-plesk-webhook"]
