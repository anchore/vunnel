from datetime import datetime
from dateutil.parser import parse

import re


class CSAFClient:
    def __init__(self):
        self.base_url = "https://ftp.suse.com/pub/projects/security/"

    def archive_date(self, dir_resp_body: str) -> datetime:
        for line in dir_resp_body.splitlines():
            if "csaf-vex.tar.bz2" in line:
                match = re.search(r"\s+(?P<date>\d\d-[A-Z][a-z][a-z]-\d\d\d\d \d\d:\d\d)\s", line)
                if match:
                    return parse(match.group("date"))
        return datetime.strptime("12-12-12", "%y-%m-%d")
