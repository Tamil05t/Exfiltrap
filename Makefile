# ExfilTrap — developer and packaging entrypoints.
SHELL := /bin/bash
PY    := .venv/bin/python

.PHONY: help test train eval demo service dashboard privileges \
        install-linux uninstall-linux desktop-dev desktop-build

help:
	@echo "ExfilTrap targets:"
	@echo "  make test           run the full pytest suite (no root needed)"
	@echo "  make train          (re)train the Random Forest model"
	@echo "  make eval           run the full evaluation (3 profiles + control)"
	@echo "  make demo           fresh demo run + dashboard (no root needed)"
	@echo "  make install-linux IFACE=eth0   one-time privileged install"
	@echo "  make uninstall-linux IFACE=eth0"
	@echo "  make desktop-dev    run the Tauri desktop app against a local service"
	@echo "  make desktop-build  build the desktop app (deb/rpm/AppImage bundles)"

test:
	$(PY) -m pytest

train:
	$(PY) tools/train_classifier.py

eval:
	$(PY) eval/run_evaluation.py

demo:
	$(PY) -m exfiltrap.service --demo --fresh-db --time-scale 120

service:
	$(PY) -m exfiltrap.service --iface $$(ip -o -4 route show default | awk '{print $$5}' | head -1)

dashboard:
	$(PY) -m exfiltrap.dashboard

privileges:
	$(PY) -m exfiltrap.privileges

install-linux:
	./tools/install_linux.sh $${IFACE:-eth0}

uninstall-linux:
	./tools/uninstall_linux.sh $${IFACE:-eth0}

desktop-dev:
	cd desktop && npm install && npm run tauri dev

desktop-build:
	cd desktop && npm install && npm run tauri build
