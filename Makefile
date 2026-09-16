.PHONY: fetch-classifier build test lint format audit

fetch-classifier:
	@bash scripts/fetch-classifier-model.sh

build:
	cargo build

test:
	cargo test --all-features

lint:
	cargo clippy --all-targets --all-features -- -D warnings

format:
	cargo fmt --all

audit:
	cargo audit
