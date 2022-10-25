"""
    This file is a helper module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Decorators:

    concurrent

    Classes:

    ProcessPool
"""

import asyncio
import time
from concurrent.futures import ProcessPoolExecutor


# run a given function concurrently
# original arguments will be substituted with an array of arguments
def concurrent(function):
    def wrapper(args):
        async def iex():
            loop = asyncio.get_running_loop()
            tasks = [loop.run_in_executor(None, function, *arg) for arg in args]
            return [await task for task in tasks]
        return asyncio.run(iex())
    return wrapper


# try-with-resources wrapper for ProcessPoolExecutor
class ProcessPool:

    def __init__(self, max_workers):
        self.executor = ProcessPoolExecutor(max_workers=max_workers)

    # run a given function in parallel
    # original arguments will be substituted with an array of arguments
    def run(self, function, args, progressbar):
        # create tasks
        tasks = [self.executor.submit(function, *arg) for arg in args]
        # wait for tasks to finish
        start = time.time()
        while any(not task.done() for task in tasks):
            progressbar.turn_spinner()
            time.sleep(0.1)
        end = time.time()
        return end - start, [task.result() for task in tasks]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.executor.__exit__(exc_type, exc_val, exc_tb)
