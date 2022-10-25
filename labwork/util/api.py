"""
    This file is a helper module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Classes:

    LabworkAPI
"""

import requests

# http content headers
request_headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}


# try-with-resources wrapper for session
# only make tls handshake once
class LabworkAPI:

    def __init__(self, config):
        # setup session & paths
        self.session = requests.Session()
        self.assignments_path = config.endpoint + "/assignment/" + config.client_id + "/" + config.labwork_id
        self.submission_path = config.endpoint + "/submission/"
        self.oracle_path = config.endpoint + "/oracle/"

    # /assignment route
    def get_assignments(self):
        with self.session.get(
                self.assignments_path,
                headers=request_headers
        ) as response:
            assert response.status_code == 200, response.text
            return response.json()

    # /submission route
    def post_submission(self, case_id, body):
        with self.session.post(
                self.submission_path + case_id,
                headers=request_headers, json=body
        ) as response:
            assert response.status_code == 200, response.text
            return response.json()

    # /oracle route
    def query_oracle(self, case_type, body):
        with self.session.post(
                self.oracle_path + case_type,
                headers=request_headers, json=body
        ) as response:
            assert response.status_code == 200, response.text
            return response.json()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # close session when exiting when clause
        self.session.close()
