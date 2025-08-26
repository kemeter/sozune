FROM rust:latest as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:sid-slim

COPY --from=builder /app/target/release/sozune /sozune

EXPOSE 80
ENTRYPOINT ["/sozune"]
