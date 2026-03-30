MODE ?= virtual

.PHONY: build chrome firefox clean run run-physical install

build: chrome firefox

chrome: dist/chrome
firefox: dist/virtual-webauthn.xpi

dist/chrome: extension/*
	@rm -rf $@
	@mkdir -p $@
	cp extension/* $@/

dist/virtual-webauthn.xpi: extension/*
	@mkdir -p dist
	cd extension && zip -r ../$@ . -x '.*'

clean:
	rm -rf dist/

run:
	cd server && python main.py --mode $(MODE)

run-physical:
	cd server && python main.py --mode physical

install:
	pip install -r requirements.txt
