/*
 * SPDX-FileCopyrightText: 2026 Linutronix GmbH
 *
 * SPDX-License-Identifier: 0BSD
 */

#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenSigHub");
MODULE_DESCRIPTION("Minimal module for testing");
MODULE_VERSION("0.1");

static int __init minimal_init(void) {
    return 0;
}

module_init(minimal_init);
