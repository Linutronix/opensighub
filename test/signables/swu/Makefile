# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

BUILD_DIR := ../../build
OUT_DIR := $(BUILD_DIR)/swu
TARGET := $(OUT_DIR)/out.swu

$(TARGET): sw-description message.txt | $(OUT_DIR)
	swugenerator -o $(abspath $(TARGET)) -s sw-description -a . create

$(OUT_DIR):
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)

all: $(TARGET)
