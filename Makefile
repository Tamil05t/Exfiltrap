# ExfilTrap — developer and packaging entrypoints.
SHELL := /bin/bash
PY    := .venv/bin/python
IFACE ?=

.PHONY: help test verify verify-menu attack mitigation-test train eval service \
        dashboard privileges install-linux uninstall-linux desktop-dev \
        desktop-build arch-package flatpak

help:
	@echo "ExfilTrap targets (detection service runs as root):"
	@echo "  make test                       full pytest suite"
	@echo "  make verify                     verify every documented CLAIM (exit 1 if any is falsified)"
	@echo "  make verify-menu                same, as an interactive menu (category by category)"
	@echo "  make attack                     attack simulator menu (needs the running engine)"
	@echo "  make mitigation-test            every mitigation backend, offline, no root needed"
	@echo "  make train                      (re)train the Random Forest model"
	@echo "  make eval                       evaluation (3 profiles + control)"
	@echo "  make service                    live service (sudo; auto-detects iface)"
	@echo "  make dashboard                  dashboard against the local DB"
	@echo "  make install-linux IFACE=eth0   one-time privileged install"
	@echo "  make uninstall-linux IFACE=eth0"
	@echo "  make desktop-build              Tauri desktop app (deb/rpm)"
	@echo "  make arch-package               Arch package (needs makepkg)"
	@echo "  make flatpak                    Flatpak bundle (needs flatpak-builder + docker)"

test:
	$(PY) -m pytest

# `make test` proves the CODE behaves; `make verify` proves the CLAIMS are true.
# A suite can be 100% green while a README headline number is unreproducible,
# so these are deliberately separate jobs. Exit code 1 if any claim is
# falsified (SKIP is not a failure); the evidence is printed for every claim.
verify:
	$(PY) tools/verify_console.py --all

verify-menu:
	$(PY) tools/verify_console.py

# Attack simulation needs a RUNNING engine (it sends real DNS and reads the
# verdicts back from the API); the mitigation self-test needs neither root nor
# an engine — it drives the shipped response classes in-process.
attack:
	$(PY) tools/demo_console.py

mitigation-test:
	$(PY) tools/demo_console.py --mitigations

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

arch-package:
	cd packaging/arch && makepkg -f

flatpak:
	bash packaging/flatpak/build-flatpak.sh --bundle
