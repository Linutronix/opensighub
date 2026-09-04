# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

SUBDIRS := efi hab4 ko elf rpi-boot-container apt-signing-archive
SUBTARGETS := all clean

$(SUBTARGETS): $(SUBDIRS)
$(SUBDIRS):
	cd $@ && $(MAKE) $(MAKECMDGOALS)

.PHONY: $(SUBTARGETS) $(SUBDIRS)
