.DEFAULT_GOAL := build

clean: 
	cargo clean

build:
	cargo build
	cargo doc

test:
	cargo test
