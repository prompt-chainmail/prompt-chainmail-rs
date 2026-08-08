.PHONY: fetch-classifier build test lint

fetch-classifier:
	@bash scripts/fetch-classifier-model.sh

build:
	cargo build

test:
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings
