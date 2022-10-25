"""
    This file is a helper module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Classes:

    Log
"""


# helper class for ProgressBar.insert in combination with a given identifier
class Log:

    def __init__(self, identifier, progress_bar):
        self.identifier = identifier
        self.progress_bar = progress_bar

    def log(self, text, required_verbosity):
        self.progress_bar.insert(f"[#{self.identifier}]\t{text}\n", required_verbosity)
