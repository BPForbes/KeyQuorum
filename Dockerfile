# syntax=docker/dockerfile:1.7
#
# The hosted KeyQuorum relay: the provider-capable `keyquorum` binary with
# the MongoDB store, in a minimal non-root image.
#
#   docker build -t keyquorum-relay:local .
#
# The image holds a binary and nothing else. Everything a running relay is
# trusted with arrives at run time and is never baked in:
#   - the relay private key, through a mounted secret file named by
#     --relay-key (or KEYQUORUM_RELAY_KEY);
#   - provider.kqcert and provider.kqrl, mounted read-only (public, but
#     integrity-sensitive: they are signed, so mount them from a source you
#     control);
#   - the MongoDB connection string, through a mounted secret file named by
#     --mongodb-uri-file (or KEYQUORUM_MONGODB_URI_FILE).
# The provider-root private key and the kql_… operator lock never belong in
# a container, an image or a cluster. The container filesystem is not
# authoritative for anything: with MongoDB configured the SQLite file is
# not opened at all, and the root filesystem can be read-only.
#
# The operator console the relay serves at /console/ (relay-console/) is
# built first and embedded into the binary by build.rs; it is public static
# files and holds no secret.
#
# Build arguments:
#   RUST_VERSION   the Rust toolchain tag of the builder image
#   NODE_VERSION   the Node.js tag of the console builder image
#   FEATURES       cargo features of the binary (provider is required to
#                  serve; mongodb for the hosted store)

ARG RUST_VERSION=1.97
ARG NODE_VERSION=22
ARG FEATURES=provider,mongodb

# --- console --------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS console
WORKDIR /console
COPY relay-console/package.json relay-console/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts
COPY relay-console/ ./
RUN npm run build

# --- build ----------------------------------------------------------------
FROM rust:${RUST_VERSION}-bookworm AS build
ARG FEATURES
WORKDIR /src
# The dependency graph first, so a source change does not refetch it.
COPY Cargo.toml Cargo.lock build.rs deny.toml ./
COPY src ./src
COPY --from=console /console/dist ./relay-console/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release --features "${FEATURES}" --bin keyquorum \
    && install -m 0755 target/release/keyquorum /out-keyquorum

# --- runtime --------------------------------------------------------------
# Distroless: a C runtime, CA certificates and nothing else (no shell, no
# package manager). `nonroot` is uid 65532.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out-keyquorum /usr/local/bin/keyquorum
USER 65532:65532
# The relay serves plain HTTP; TLS terminates at the ingress in front of
# it, which is why `serve` is given --behind-tls-proxy in the chart.
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/keyquorum"]
CMD ["host", "serve", "--bind", "0.0.0.0:8787", "--behind-tls-proxy"]
