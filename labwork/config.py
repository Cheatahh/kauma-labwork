"""
    This file is a config module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
"""

import argparse
import sys

name = "Response program (T3INF9004: Cryptanalysis und Method-Audit)\nAuthors: DHBW Students 200374 & 200357 (2022)"

# parse cli arguments
parser = argparse.ArgumentParser(description=name)
parser.add_argument(dest="endpoint", action="store", type=str,
                    help="labwork endpoint, for example https://example.com/endpoint")
parser.add_argument(dest="client_id", action="store", type=str,
                    help="client uuid, for example 'cafebabe-0000-0000-0000-000000000000'")
parser.add_argument(dest="labwork_id", action="store", type=str,
                    help="labwork identifier, for example 'labwork01'")
parser.add_argument("-v", "--verbose", dest="verbosity", action="count", default=0,
                    help="increase verbosity (up to 3 times)")
parser.add_argument("-p", "--processes", dest="process_count", action="store", type=int, default=1,
                    help="number of processes to use for parallel processing")
parser.add_argument("--debug", dest="debug", action="store_true", default=False,
                    help="debug mode")
config = parser.parse_args(sys.argv[1:])

# extracted config values to ease access
endpoint = config.endpoint
client_id = config.client_id
labwork_id = config.labwork_id
verbosity = max(0, config.verbosity)
process_count = max(1, config.process_count)
debug = config.debug
