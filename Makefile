# ExfilTrap — developer and packaging entrypoints.
SHELL := /bin/bash
PY    := .venv/bin/python
IFACE ?=

.PHONY: help test train eval service dashboard privileges \
        install-linux uninstall-linux desktop-dev desktop-build

help:
	@echo "ExfilTrap targets (detection service runs as root):"
	@echo "  make test                       full pytest suite"
	@echo "  make train                      (re)train the Random Forest model"
	@echo "  make eval                       evaluation (3 profiles + control)"
	@echo "  make service                    live service (sudo; auto-detects iface)"
	@echo "  make dashboard                  dashboard against the local DB"
	@echo "  make install-linux IFACE=eth0   one-time privileged install"
	@echo "  make uninstall-linux IFACE=eth0"
	@echo "  make desktop-build              Tauri desktop app (deb/rpm/AppImage)"

test:
	$(PY) -m pytest

train:
	$(PY) tools/train_classifier.py

eval:
	$(PY) eval/run_evaluation.py

service:
	sudo $(PY) -m exfiltrap.service $(if $(IFACE),--iface $(IFACE),)

dashboard:
	$(PY) -m exfiltrap.dashboard

privileges:
	$(PY) -m exfiltrap.privileges

install-linux:
	./tools/install_linux.sh $(IFACE)

uninstall-linux:
	./tools/uninstall_linux.sh $(IFACE)

desktop-dev:
	cd desktop && npm install && npm run tauri dev

desktop-build:
	cd desktop && npm install && npm run tauri build
