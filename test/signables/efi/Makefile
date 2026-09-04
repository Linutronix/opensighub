# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

CC = clang
CFLAGS = -target x86_64-pc-win32-coff -fno-stack-protector -fshort-wchar -mno-red-zone
LD = lld-link
LDFLAGS = -filealign:16 -subsystem:efi_application -nodefaultlib -dll -entry:efi_main

BUILD_DIR := ../../build
OUT_DIR := $(BUILD_DIR)/efi

SRCS = minimal.c
OBJS = $(addprefix $(OUT_DIR)/,$(SRCS:.c=.o))
TARGET = $(OUT_DIR)/minimal.efi

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -out:$(TARGET)

$(OUT_DIR)/%.o: %.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT_DIR):
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)
