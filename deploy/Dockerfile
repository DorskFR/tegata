FROM node:26-trixie-slim AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

FROM rust:1.99-slim-trixie AS server
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY --from=ui /ui/build ui/build
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=server /app/target/release/tegata /usr/local/bin/tegata
ENV TEGATA_LISTEN=0.0.0.0:8080 TEGATA_DATA_DIR=/data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/tegata"]
