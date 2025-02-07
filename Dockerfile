# Stage 1: Build the application
FROM rust:1.67 as builder

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy only the Cargo manifests to cache dependencies.
COPY Cargo.toml Cargo.lock ./

# Create a dummy main file to build dependencies.
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this step is cached unless Cargo.toml/lock changes)
RUN cargo build --release

# Remove the dummy file and copy the full source code.
RUN rm -rf src
COPY . .

# Build the actual binary
RUN cargo build --release

# Stage 2: Create a minimal runtime image
FROM debian:buster-slim

# Install required runtime dependencies (e.g. OpenSSL libraries)
RUN apt-get update && apt-get install -y libssl1.1 ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage.
# Note: The binary is expected to be named after your package, "rust".
COPY --from=builder /usr/src/app/target/release/rust /usr/local/bin/rust

# Expose the port your application listens on (adjust as necessary)
EXPOSE 8000

# Run the binary when the container starts.
CMD ["rust"]
