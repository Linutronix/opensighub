# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

# create a fat filesystem as rpi-boot-container with 96 MiB
minimal_rpi_boot_container:
	mkfs.fat -C boot.img 32768

.PHONY: clean
clean:
	rm boot.img

all: minimal_rpi_boot_container
