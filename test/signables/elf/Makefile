# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

CC    ?= gcc
STRIP ?= strip

SRC ?= minimal.c

ELF       := minimal.elf
UUID_FILE := .uuid

.PHONY: all clean uuid
all: $(UUID_FILE) $(ELF) optee_elf

$(UUID_FILE):
	uuidgen | tr 'A-Z' 'a-z' > $@

$(ELF): $(SRC)
	$(CC) -o $@ $<

optee_elf: $(ELF) $(UUID_FILE)
	cp $(ELF) "$$(cat $(UUID_FILE)).stripped.elf"
	$(STRIP) --strip-all "$$(cat $(UUID_FILE)).stripped.elf"

uuid:
	@cat $(UUID_FILE) 2>/dev/null || true

clean:
	rm -f $(ELF) *.stripped.elf $(UUID_FILE)
