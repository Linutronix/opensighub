# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

CC    ?= gcc
STRIP ?= strip

SRC ?= minimal.c

BUILD_DIR := ../../build
OUT_DIR   := $(BUILD_DIR)/elf
ELF       := $(OUT_DIR)/minimal.elf
UUID_FILE := $(OUT_DIR)/.uuid

.PHONY: all clean uuid
all: $(UUID_FILE) $(ELF) optee_elf

$(OUT_DIR):
	mkdir -p $@

$(UUID_FILE): | $(OUT_DIR)
	uuidgen | tr 'A-Z' 'a-z' > $@

$(ELF): $(SRC) | $(OUT_DIR)
	$(CC) -o $@ $<

optee_elf: $(ELF) $(UUID_FILE)
	cp $(ELF) "$(OUT_DIR)/$$(cat $(UUID_FILE)).stripped.elf"
	$(STRIP) --strip-all "$(OUT_DIR)/$$(cat $(UUID_FILE)).stripped.elf"

uuid:
	@cat $(UUID_FILE) 2>/dev/null || true

clean:
	rm -rf $(OUT_DIR)
