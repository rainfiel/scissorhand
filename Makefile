.PHONY: inject hook

.ONESHELL:
inject:
	cd inject && make all

.ONESHELL:
hook:
	cd hook && make install

all: inject hook
	cd inject && python test.py

