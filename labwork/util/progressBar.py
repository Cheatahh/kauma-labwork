"""
    This file is a helper module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Classes:

    ProgressBar
"""

import shutil
import sys


# simple console ProgressBar
class ProgressBar:
    spinner = ["|", "/", "-", "\\"]

    # helper class to simulate a shared value between processes
    # used if multiprocessing_manager is None
    class Value:
        def __init__(self, value):
            self.value = value

    # helper class to simulate a shared lock between processes
    # used if multiprocessing_manager is None
    class Lock:
        def __init__(self):
            pass

        def acquire(self):
            pass

        def release(self):
            pass

    # if multiprocessing_manager is not None, the ProgressBar state will be shared between processes
    def __init__(self, name, pb_start, pb_length, max_value, verbosity_level=0, multiprocessing_manager=None):
        self.name = name
        self.max_value = max_value
        if multiprocessing_manager is not None:
            self.current = multiprocessing_manager.Value('i', 0)
            self.passed = multiprocessing_manager.Value('i', 0)
            self.spinner_value = multiprocessing_manager.Value('i', 0)
            self.lock = multiprocessing_manager.Lock()
        else:
            self.current = ProgressBar.Value(0)
            self.passed = ProgressBar.Value(0)
            self.spinner_value = ProgressBar.Value(0)
            self.lock = ProgressBar.Lock()
        self.pb_length = pb_length
        self.spacing = " " * max(pb_start - len(name), 0)
        self.charsPerStep = pb_length / max_value
        self.verbosityLevel = verbosity_level
        self.insert("")

    # insert a piece of text above the process bar
    # while this class is used, any output to the console should flow through ProgressBar.insert()
    def insert(self, text, required_verbosity=-1):
        if required_verbosity <= self.verbosityLevel:
            current_progress = int(self.charsPerStep * self.current.value)
            # create one large string to avoid multiple console writes
            result = f"""\r{' ' * shutil.get_terminal_size().columns}\r{text}{
            self.spinner[self.spinner_value.value % len(self.spinner)] if self.passed.value < self.max_value else "✓"} '{
            self.name}'{self.spacing}[{'=' * (current_progress - 1)}{'>' if 0 < current_progress else ''}{
            ' ' * (self.pb_length - current_progress)}] {self.current.value}/{self.max_value} ({
            int(self.current.value / self.max_value * 100)}%) | {
            f'Passed {self.passed.value}/{self.max_value} ({int(self.passed.value / self.max_value * 100)}%)'
            if self.passed.value < self.max_value else 'PASSED             '}"""
            sys.stdout.write(result)
            sys.stdout.flush()

    # increment the current process bar state
    def step(self, passed, insert=""):
        self.lock.acquire()
        self.current.value += 1
        if passed:
            self.passed.value += 1
        self.lock.release()
        self.insert(insert)

    # turn the spinner by one
    def turn_spinner(self):
        self.lock.acquire()
        self.spinner_value.value += 1
        self.lock.release()
        self.insert("")

    # finish printing, console can be used regularly again
    @staticmethod
    def finish():
        print()
