# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

.ONESHELL:

BUILD_DIR := ../../build
APT_DIR := $(BUILD_DIR)/apt-signing-archive

UNSIGNED_DIR := opensighub-test-package-unsigned
TEMPLATE_DIR := opensighub-test-package-signed-template

UNSIGNED_DEB := $(APT_DIR)/$(UNSIGNED_DIR)_1.0-1_amd64.deb
TEMPLATE_DEB := $(APT_DIR)/$(TEMPLATE_DIR)_1.0-1_amd64.deb

all: $(APT_DIR)/Packages

opensighub-test-package: $(UNSIGNED_DEB) $(TEMPLATE_DEB)

.PHONY: FORCE
FORCE:

$(BUILD_DIR)/efi/minimal.efi: FORCE
	$(MAKE) -C ../efi

$(BUILD_DIR)/hab4/minimal_hab4.bin: FORCE
	$(MAKE) -C ../hab4

$(BUILD_DIR)/ko/minimal.ko: FORCE
	$(MAKE) -C ../ko

$(UNSIGNED_DEB) $(TEMPLATE_DEB) &: $(UNSIGNED_DIR)/DEBIAN/control \
		$(TEMPLATE_DIR)/usr/share/code-signing/$(TEMPLATE_DIR)/files.json \
		$(BUILD_DIR)/efi/minimal.efi $(BUILD_DIR)/hab4/minimal_hab4.bin \
		../hab4/minimal_hab4_csf.txt $(BUILD_DIR)/ko/minimal.ko
	set -euo pipefail
	mkdir -p $(APT_DIR)
	stage=$$(mktemp -d)
	trap 'rm -rf "$$stage"' EXIT
	cp -r $(UNSIGNED_DIR) "$$stage/$(UNSIGNED_DIR)"
	mkdir -p "$$stage/$(UNSIGNED_DIR)/boot/efi/test" "$$stage/$(UNSIGNED_DIR)/boot/hab4/test" "$$stage/$(UNSIGNED_DIR)/lib/modules/test"
	cp $(BUILD_DIR)/efi/minimal.efi "$$stage/$(UNSIGNED_DIR)/boot/efi/test/minimal.efi"
	cp ../hab4/minimal_hab4_csf.txt "$$stage/$(UNSIGNED_DIR)/boot/hab4/test/minimal_hab4_csf.txt"
	cp $(BUILD_DIR)/hab4/minimal_hab4.bin "$$stage/$(UNSIGNED_DIR)/minimal_hab4.bin"
	cp $(BUILD_DIR)/ko/minimal.ko "$$stage/$(UNSIGNED_DIR)/lib/modules/test/minimal.ko"
	chmod -R go-w "$$stage/$(UNSIGNED_DIR)/DEBIAN"
	cp -r $(TEMPLATE_DIR) "$$stage/$(TEMPLATE_DIR)"
	chmod 0755 "$$stage/$(TEMPLATE_DIR)/usr/share/code-signing/$(TEMPLATE_DIR)/source-template/debian/rules"
	chmod -R go-w "$$stage/$(TEMPLATE_DIR)/DEBIAN"
	dpkg-deb --build --root-owner-group "$$stage/$(UNSIGNED_DIR)" $(APT_DIR)/
	dpkg-deb --build --root-owner-group "$$stage/$(TEMPLATE_DIR)" $(APT_DIR)/

apt-signing-archive: $(APT_DIR)/Packages

$(APT_DIR)/Packages: $(UNSIGNED_DEB) $(TEMPLATE_DEB)
	cd $(APT_DIR) && dpkg-scanpackages --multiversion . >Packages

.PHONY: opensighub-test-package apt-signing-archive clean
clean:
	rm -rf $(APT_DIR)
