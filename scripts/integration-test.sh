#!/bin/sh
# Run the unit and end-to-end tests inside a Debian 12 (Bookworm) arm64
# container, the same base as Raspberry Pi OS Bookworm.
#
# The end-to-end test runs afprustd as root, creates a test account, logs
# in through PAM and checks that sessions drop privileges.
set -eu
cd "$(dirname "$0")/.."

IMAGE=afprust-build
docker build --platform linux/arm64 -q -f packaging/docker/Dockerfile.build -t "$IMAGE" . >/dev/null

docker run --rm --platform linux/arm64 \
    -v "$PWD":/src \
    -v afprust-cargo:/usr/local/cargo/registry \
    -v afprust-target:/src/target \
    -v afprust-itdata:/srv/afprust-it \
    "$IMAGE" sh -euc '
        id macuser >/dev/null 2>&1 || useradd -m -s /bin/sh macuser
        echo "macuser:Pa55word" | chpasswd
        install -m 644 packaging/pam.d/afprust /etc/pam.d/afprust
        cargo test --quiet "$@"
        AFPRUST_IT=1 AFPRUST_IT_USER=macuser AFPRUST_IT_PASS=Pa55word \
            AFPRUST_IT_DIR=/srv/afprust-it \
            cargo test --quiet --test integration -- --nocapture
    ' sh "$@"
