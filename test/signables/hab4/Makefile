# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

BUILD_DIR := ../../build
OUT_DIR := $(BUILD_DIR)/hab4
TARGET := $(OUT_DIR)/minimal_hab4.bin

# CSF signs arbitrary content, so just prepare a zero filled file
$(TARGET): | $(OUT_DIR)
	dd if=/dev/zero of=$@ bs=8  count=1

$(OUT_DIR):
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)

all: $(TARGET)
