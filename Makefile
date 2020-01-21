init:
	pip install -r requirements.txt

install:
	maturin develop

TARGET = $(wildcard target/wheels/subkey-*.whl)

test: install
	pytest

PYPI_TOKEN = $(shell grep -oP "password = \K.*" ~/.pypirc)

publish: init
	maturin publish -i python3.8 --username __token__ --password $(PYPI_TOKEN)

# Clean python build files
clean-build:
	rm -rf substratum.egg-info
	rm -rf build
	rm -rf dist
	rm -rf .eggs

clean-rust:
	cargo clean

clean: clean-rust clean-build

.PHONY: build clean clean-rust clean-build
