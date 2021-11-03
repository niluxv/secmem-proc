#!/usr/bin/env just --justfile

check:
    cargo +stable check
    cargo +nightly check --all-features

test:
    cargo +nightly test --no-default-features --features dev
    cargo +nightly test --all-features

full-test: test
    env CC="clang" env CFLAGS="-fsanitize=address -fno-omit-frame-pointer" env RUSTFLAGS="-C target-cpu=native -Z sanitizer=address" cargo +nightly test -Z build-std --target x86_64-unknown-linux-gnu --tests --all-features
    env CC="clang" env CFLAGS="-fsanitize=memory -fno-omit-frame-pointer" env RUSTFLAGS="-C target-cpu=native -Z sanitizer=memory" cargo +nightly test -Z build-std --target x86_64-unknown-linux-gnu --tests --all-features

doc:
    cargo +nightly doc --all-features

doc-open:
    cargo +nightly doc --all-features --open

fmt:
    cargo +nightly fmt

fmt-check:
    cargo +nightly fmt -- --check

clippy:
    cargo +nightly clippy --all-features

full-check: check full-test doc clippy fmt-check

clean:
    cargo clean

generate-readme:
    cargo doc2readme
