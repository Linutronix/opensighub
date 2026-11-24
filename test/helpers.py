# SPDX-FileCopyrightText: 2026 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import time
from collections.abc import Callable


def wait_for(condition: Callable[[], bool], timeout: float = 10, interval: float = 0.05) -> None:
    """Poll until condition() is true. Fail the test if it is not within timeout seconds."""
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, f"condition not met within {timeout}s"
        time.sleep(interval)
