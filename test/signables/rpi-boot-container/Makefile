# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

BUILD_DIR := ../../build
OUT_DIR := $(BUILD_DIR)/rpi-boot-container
TARGET := $(OUT_DIR)/boot.img

# create a fat filesystem as rpi-boot-container with 96 MiB
$(TARGET): | $(OUT_DIR)
	mkfs.fat -C $@ 32768

$(OUT_DIR):
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)

all: $(TARGET)
