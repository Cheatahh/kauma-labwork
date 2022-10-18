"""
    This file is a helper module for response program (T3INF9004: Cryptanalyses und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Classes:

    ProgressBar
"""

import sys


# ProgressBar for pretty printing
class ProgressBar:

    # constructor
    def __init__(self, name, indent, total):
        self.name = name
        self.indent = indent + 1
        self.total = total
        self.current = 0
        self.passed = 0
        self.charsPerStep = 20.0 / total
        self.update()

    # clear previous line and print progress bar
    def update(self, insert=""):
        current_progress = int(self.charsPerStep * self.current)
        result = "\r%s'%s'%s[%s%s%s] %d/%d (%d%%) | %s" % (
            insert, self.name, " " * self.indent, "=" * (current_progress - 1),
            ">" if 0 < current_progress else "", " " * (20 - current_progress),
            self.current, self.total, self.current / self.total * 100,
            "Passed %d/%d (%d%%)" % (self.passed, self.total, self.passed / self.total * 100)
            if self.passed < self.total else "PASSED             "
        )
        sys.stdout.write(result)
        sys.stdout.flush()

    # increment progress bar
    def step(self, insert, passed):
        self.current += 1
        if passed:
            self.passed += 1
        self.update(insert)

    # finish up progress bar printing
    def finish(self):
        self.current = self.total
        self.update()
        print()
