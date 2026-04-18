# Author: Junnoh Lee <pluruel@gmail.com>
# Copyright (c) 2026 Junnoh Lee. All rights reserved.
FROM rust:1.90-slim-bookworm AS build

WORKDIR /src

# Cache deps separately from source.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src src/bin && \
    echo 'fn main() {}' > src/main.rs && \
    echo 'fn main() {}' > src/bin/keygen.rs && \
    echo '' > src/lib.rs && \
    cargo build --release --bins && \
    rm -rf src

COPY . .
RUN touch src/main.rs src/bin/keygen.rs src/lib.rs && \
    cargo build --release --bins && \
    strip target/release/auth_rs target/release/keygen

FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app
COPY --from=build /src/target/release/auth_rs /app/auth_rs
COPY --from=build /src/target/release/keygen /app/keygen

EXPOSE 8001
USER nonroot:nonroot
ENTRYPOINT ["/app/auth_rs"]
