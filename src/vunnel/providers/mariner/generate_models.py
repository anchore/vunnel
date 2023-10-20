import os
import tempfile
from subprocess import PIPE, Popen

import requests

MARINER_URL_BASE = "https://raw.githubusercontent.com/microsoft/CBL-MarinerVulnerabilityData/main/{}"
MARINER_URL_FILENAME = "cbl-mariner-{}-oval.xml"


def download_version(version: str, dest_dir: str) -> None:
    filename = MARINER_URL_FILENAME.format(version)
    url = MARINER_URL_BASE.format(filename)
    r = requests.get(url, timeout=125)
    destination = os.path.join(dest_dir, filename)
    with open(destination, "wb") as w:
        w.write(r.content)


def main() -> None:
    versions = ["2.0"]
    dest_path = tempfile.TemporaryDirectory()
    for v in versions:
        download_version(v, dest_path.name)

    script_dir = os.path.realpath(os.path.dirname(__file__))
    args = [
        "xsdata",
        "generate",
        dest_path.name,
        "-r",
        "--relative-imports",
        "--compound-fields",
        "--package",
        "model.generated",
        "--structure-style",
        "single-package",
    ]
    process = Popen(args=args, stderr=PIPE, stdout=PIPE, cwd=script_dir)
    stdout, stderr = process.communicate()
    print(stdout)
    print(stderr)


if __name__ == "__main__":
    main()
