"""
    This file is a helper module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Classes:

    API
"""
import argparse
import sys

import requests

# setup config from system args
parser = argparse.ArgumentParser(description="Response program (T3INF9004: Cryptanalyses und Method-Audit)\nAuthors: "
                                             "DHBW Students 200374 & 200357 (2022)")
parser.add_argument(dest="endpoint", action="store", type=str,
                    help="labwork endpoint, for example https://example.com/endpoint")
parser.add_argument(dest="client_id", action="store", type=str,
                    help="client UUID, for example 'cafebabe-0000-0000-0000-000000000000'")
parser.add_argument(dest="labwork", action="store", type=str,
                    help="labwork name, for example 'labwork01'")
parser.add_argument("-v", "--verbose", dest="verbosity", action="count", default=0,
                    help="increase verbosity (up to 3 times)")
args = parser.parse_args(sys.argv[1:])

endpoint = args.endpoint
client_id = args.client_id
labwork = args.labwork
verbosity = args.verbosity

# http content headers
request_headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# print config
if verbosity > 0:
    print("------ CONFIG ------")
    print("Endpoint:", endpoint)
    print("Client ID:", client_id)
    print("Assignment Name:", labwork)


# try-with-resources wrapper for session
# only make tls handshake once
class API:

    # setup session
    session = requests.Session()

    def get_assignments(self):
        with self.session.get(
                endpoint + "/assignment/" + client_id + "/" + labwork,
                headers=request_headers
        ) as response:
            assert response.status_code == 200, response.text
            return response.json()

    def post_submission(self, case_id, body):
        with self.session.post(
                endpoint + "/submission/" + case_id,
                headers=request_headers, json=body
        ) as response:
            assert response.status_code == 200, response.text
            return response.json()

    def query_oracle(self, case_type, body):
        with self.session.post(
                endpoint + "/oracle/" + case_type,
                headers=request_headers, json=body
        ) as response:
            assert response.status_code == 200, response.text
            return response.json()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()
