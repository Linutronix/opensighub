# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

BUILD_DIR := ../../build
OUT_DIR := $(BUILD_DIR)/ko
KDIR := $(lastword $(sort $(wildcard /lib/modules/*/build)))

all: $(OUT_DIR)/minimal.ko

$(OUT_DIR)/minimal.ko: minimal.c | $(OUT_DIR)
	ln -sf $(CURDIR)/minimal.c $(OUT_DIR)/minimal.c
	echo 'obj-m := minimal.o' >$(OUT_DIR)/Kbuild
	$(MAKE) -C $(KDIR) M=$(abspath $(OUT_DIR)) modules

$(OUT_DIR):
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)
