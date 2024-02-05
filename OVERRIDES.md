# Vunnel Data Overrides

This document describes the process for overriding provider data in Vunnel.

## Why Override Data

## How to Override Data

Commands to override data live under the `vunnel override` namespace. The following commands are available:

## Example Workflow: Making Apache Chainsaw match CVE-2020-9493

1. Determine which provider data to override. A good default is to override the `nvd` provider data.
2. If you haven't already, pull down the NVD data:

    ```bash
    vunnel run nvd
    ```
3. Find the CVE you want to override. Usually, this comes from a reported false negative. In this case, we'll use CVE-2020-9493.
4.  Tell vunnel to create a stub override file:

    ```bash
    vunnel override create nvd CVE-2020-9493
    # then edit the file
    # or edit the file directly, since the path is printed to stdout
    vim $(vunnel override create nvd CVE-2020-9493)
    ```
5. Edit the override file to contain the fields you need (see example finished file below).

6. Apply the override and verify that matching data looks right:

    ```bash
    make update-db overrides-only=true
    sqlite3 .cache/grype/5/vulnerability.db
    grype <some image exhibiting false negative>
    ```

7. When satisfied, publish the image override:

        ```bash
        cd ../vunnel-data-overrides
        git checkout -b nvd-2020-9493-chainsaw
        git add .
        git commit -m "Add override for CVE-2020-9493"
        git push origin nvd-2020-9493-chainsaw
        # then open a PR
        ```

## Example Override File

```json
{
  "vuln_id": "CVE-2020-9493",
  "provider": "nvd",
  "upstream_record_sha256": "8ee4e53e39ae3b8c3c8d7d57e3df45db361aab898acdd9a01824a2db74bfae05",
  "additional_entries": [
    {
      "package": {
        "identifier": "pkg:maven/log4j/apache-chainsaw"
      },
      "affected": [
        {
          "version_constraint": "< 2.1.0",
          "patched": "2.1.0"
        }
      ]
    }
  ]
}
```
