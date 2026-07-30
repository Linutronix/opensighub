# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

# CSF signs arbitrary content, so just prepare a zero filled file
minimal_hab4.bin:
	dd if=/dev/zero of=$@ bs=8  count=1

.PHONY: clean
clean:
	rm *.bin

all: minimal_hab4.bin
