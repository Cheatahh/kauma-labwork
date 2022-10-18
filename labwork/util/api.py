"""
    This file is a helper module for response program (T3INF9004: Cryptanalyses und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Classes:

    API
"""
import sys

import requests

# setup config from system args
if not 4 <= len(sys.argv) <= 5:
    print("Usage: <endpoint> <client-id> <assignment> <optional --no-debug>")
    exit(1)

endpoint = sys.argv[1]
client_id = sys.argv[2]
labwork = sys.argv[3]
debug = sys.argv[4] != "--no-debug" if len(sys.argv) == 5 else True

# http content headers
request_headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# print config
if debug:
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
