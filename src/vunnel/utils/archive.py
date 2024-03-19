import os
import tarfile

def filter_path_traversal(tarinfo: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
    # we do not expect any relative file paths that would result in the clean
    # path being different from the original path
    # e.g.
    #  expected:   results/results.db
    #  unexpected: results/../../../../etc/passwd
    # we filter (drop) any such entries

    if tarinfo.name != os.path.normpath(tarinfo.name):
        return None
    return tarinfo

def safe_extract_tar(tar: tarfile.TarFile, destination_dir: str) -> None:
    tar.extractall(destination_dir, filter=filter_path_traversal)
