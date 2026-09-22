# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

BUILD_DIR := ../../build
OUT_DIR := $(BUILD_DIR)/rpi-eeprom
TARGET := $(OUT_DIR)/pieeprom.bin

$(TARGET): | $(OUT_DIR)
	dd if=/dev/zero of=$@ bs=1k count=64

$(OUT_DIR):
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)

all: $(TARGET)
