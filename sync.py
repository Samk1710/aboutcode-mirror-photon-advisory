#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from aboutcode.pipeline import BasePipeline, LoopProgress

ROOT_PATH = Path(__file__).parent
ADVISORIES_PATH = ROOT_PATH / "advisories"
TIMESTAMPS_FILE = ROOT_PATH / "upstream_timestamps.json"

YEAR_REGEX = re.compile(r'<a href="(20\d{2})/">')
ENTRY_REGEX = re.compile(r'<a href="([^"]+\.json)">[^<]+</a>\s+(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2})')

HEADERS = {
    "Accept": "application/json, text/html",
}
REQUEST_TIMEOUT = 15
BASE_URL = "https://packages.broadcom.com/photon/photon_cve_metadata/cve/"

class PhotonAdvisoryMirror(BasePipeline):
    @classmethod
    def steps(cls):
        return (
            cls.load_timestamps,
            cls.create_session,
            cls.collect_advisories,
            cls.save_timestamps,
        )

    def load_timestamps(self):
        self.timestamps = {}
        if TIMESTAMPS_FILE.exists():
            with TIMESTAMPS_FILE.open("r") as f:
                self.timestamps = json.load(f)

    def create_session(self):
        retry = Retry(
            total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.mount("https://", adapter)
        self.new_count = 0
        self.updated_count = 0

    def collect_advisories(self):
        """
        Discover missing or updated advisories across all year directories, queue them up and download them.

        Finds the filenames from the html response on the year pages and checks if they exist locally or are outdated.
    
        This method handles two cases:
        1. Missing advisories: If a file does not exist locally, it is added to ``updates_needed``.
        2. Updated advisories: If a file exists locally but its timestamp does not match the upstream timestamp, 
           it is added to  ``updates_needed``.

        The ``updates_needed`` list stores tuples of the form (download_url, local_file_path, upstream_last_modified, relative_filepath).
        """

        self.log(f"Fetching root index from {BASE_URL}")
        response = self.session.get(BASE_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        
        years = YEAR_REGEX.findall(response.text)
        updates_needed = [] 
        
        for year in years:
            year_url = f"{BASE_URL}{year}/"
            year_path = ADVISORIES_PATH / year
            year_path.mkdir(parents=True, exist_ok=True)
            
            response = self.session.get(year_url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            
            for advisory_filename, upstream_last_modified in ENTRY_REGEX.findall(response.text):
                local_file_path = year_path / advisory_filename 
                relative_filepath = f"{year}/{advisory_filename}"
                
                is_missing = not local_file_path.exists()
                is_outdated = self.timestamps.get(relative_filepath) != upstream_last_modified
                
                if is_missing or is_outdated:
                    download_url = f"{year_url}{advisory_filename}"
                    updates_needed.append(
                        (download_url, local_file_path, upstream_last_modified, relative_filepath)
                    )
            
        if not updates_needed:
            self.log("No new or updated files found. Sync is already up to date.")
            return

        self.log(f"Found {len(updates_needed)} files to download or update.")
        
        progress = LoopProgress(total_iterations=len(updates_needed), logger=self.log)
        for download_url, local_file_path, upstream_last_modified, relative_filepath in progress.iter(updates_needed):
            self.download_file(download_url, local_file_path, upstream_last_modified, relative_filepath)
                
        self.log(f"Sync complete. New: {self.new_count} | Updated: {self.updated_count}")

    def save_timestamps(self):
        with TIMESTAMPS_FILE.open("w") as f:
            json.dump(self.timestamps, f, indent=2)

    def download_file(self, download_url, local_file_path, upstream_last_modified, relative_filepath):
        """
        Fetch a single advisory file and update its timestamp in the local state.
        """
        try:
            response = self.session.get(download_url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
        except requests.exceptions.RequestException as error:
            self.log(f"Failed to download {download_url}: {error}")
            return
            
        is_new = not local_file_path.exists()
        
        with local_file_path.open("wb") as f:
            f.write(response.content)
            
        if is_new:
            self.new_count += 1
        else:
            self.updated_count += 1
            
        self.timestamps[relative_filepath] = upstream_last_modified

    def log(self, message):
        now_local = datetime.now(timezone.utc).astimezone()
        timestamp = now_local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print(f"{timestamp} {message}")

if __name__ == "__main__":
    mirror = PhotonAdvisoryMirror()
    status_code, error_message = mirror.execute()
    if error_message:
        print(error_message)
    sys.exit(status_code)
