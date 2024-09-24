import os
import tempfile
from subprocess import PIPE, Popen

import requests
from parser import VERSION_TO_FILENAME, VERSION_TO_URL


def download_version(version: str, dest_dir: str) -> None:
    filename = VERSION_TO_FILENAME[version]
    if not filename:
        raise Exception(f"mariner/azurelinux provider misconfigured: no filename for version {version}")
    url = VERSION_TO_URL[version]
    if not url:
        raise Exception(f"mariner/azurelinux provider misconfigured: no URL for version {version}")
    r = requests.get(url, timeout=125)
    destination = os.path.join(dest_dir, filename)
    with open(destination, "wb") as w:
        w.write(r.content)


def main() -> None:
    versions = ["2.0", "3.0"]
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
