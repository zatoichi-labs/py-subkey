init:
	pip install -r requirements.txt

build:
	maturin build -i python3.8

TARGET = $(wildcard target/wheels/py_subkey-*.whl)

install:
	pip install -U $(TARGET)

PYPI_TOKEN = $(shell grep -oP "password = \K.*" ~/.pypirc)

publish:
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
