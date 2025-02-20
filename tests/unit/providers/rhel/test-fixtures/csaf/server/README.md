## RHEL CSAF example server directory

The `./server` test fixture represents the RedHat CSAF
data that the Vunnel RHEL provider's CSAF client assumes will exist.

It is a subset of the files at https://security.access.redhat.com/data/csaf/v2/advisories/
with a fake .tar.zst and significantly shortened `deletions.csv` and `changes.csv`.
