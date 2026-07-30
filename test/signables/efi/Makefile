# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

CC = clang
CFLAGS = -target x86_64-pc-win32-coff -fno-stack-protector -fshort-wchar -mno-red-zone
LD = lld-link
LDFLAGS = -filealign:16 -subsystem:efi_application -nodefaultlib -dll -entry:efi_main

SRCS = minimal.c
OBJS = $(SRCS:.c=.o)
TARGET = minimal.efi

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -out:$(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET) *.lib
