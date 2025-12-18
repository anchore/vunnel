from vunnel.providers.sles.csaf_client import CSAFClient
from dateutil.parser import parse

example_dir_output = """<html>
<head><title>Index of /pub/projects/security/</title></head>
<body>
<h1>Index of /pub/projects/security/</h1><hr><pre><a href="../">../</a>
<a href="CC/">CC/</a>                                                05-Jul-2019 15:22       -
<a href="CC-15-SP4-DUD/">CC-15-SP4-DUD/</a>                                     30-Jun-2023 15:32       -
<a href="CC-15-SP4-KERNEL/">CC-15-SP4-KERNEL/</a>                                  05-Jul-2023 12:41       -
<a href="CommonCriteria/">CommonCriteria/</a>                                    17-Jul-2012 14:22       -
<a href="STIG/">STIG/</a>                                              03-Feb-2021 11:02       -
<a href="TC/">TC/</a>                                                17-Jan-2006 14:31       -
<a href="csaf/">csaf/</a>                                              16-Dec-2025 13:32       -
<a href="csaf-vex/">csaf-vex/</a>                                          15-Dec-2025 01:07       -
<a href="cve/">cve/</a>                                               30-Apr-2013 14:08       -
<a href="cvrf/">cvrf/</a>                                              16-Dec-2025 18:51       -
<a href="cvrf-cve/">cvrf-cve/</a>                                          15-Dec-2025 00:14       -
<a href="cvrf1.2/">cvrf1.2/</a>                                           16-Dec-2025 18:51       -
<a href="keys/">keys/</a>                                              14-May-2024 11:21       -
<a href="laus/">laus/</a>                                              01-Dec-2005 14:32       -
<a href="osc2016/">osc2016/</a>                                           21-Jun-2016 13:40       -
<a href="osv/">osv/</a>                                               16-Dec-2025 18:26       -
<a href="oval/">oval/</a>                                              16-Dec-2025 06:25       -
<a href="sbom-beta/">sbom-beta/</a>                                         24-Mar-2023 15:54       -
<a href="secure-boot/">secure-boot/</a>                                       04-Sep-2013 12:12       -
<a href="shim/">shim/</a>                                              16-Jul-2020 11:31       -
<a href="yaml/">yaml/</a>                                              16-Dec-2025 18:31       -
<a href="advisory-map.csv">advisory-map.csv</a>                                   16-Dec-2025 17:59     19M

<a href="advisory-map.csv.bz2">advisory-map.csv.bz2</a>                               16-Dec-2025 17:59      1M
<a href="csaf-vex.tar.bz2">csaf-vex.tar.bz2</a>                                   15-Dec-2025 01:07    334M
<a href="csaf-vex.tar.bz2.asc">csaf-vex.tar.bz2.asc</a>                               16-Dec-2025 18:35     819
<a href="csaf.tar.bz2">csaf.tar.bz2</a>                                       16-Dec-2025 15:20    110M
<a href="csaf.tar.bz2.asc">csaf.tar.bz2.asc</a>                                   16-Dec-2025 15:21     819
<a href="cvrf-cve.tar.bz2">cvrf-cve.tar.bz2</a>                                   05-Nov-2025 07:22    208M
<a href="cvrf.tar.bz2">cvrf.tar.bz2</a>                                       16-Dec-2025 08:49    200M
<a href="cvrf.tar.bz2.asc">cvrf.tar.bz2.asc</a>                                   16-Dec-2025 08:49     819
<a href="cvrf1.2.tar.bz2">cvrf1.2.tar.bz2</a>                                    16-Dec-2025 09:49    202M
<a href="cvrf1.2.tar.bz2.asc">cvrf1.2.tar.bz2.asc</a>                                16-Dec-2025 09:49     819
<a href="osv.tar.bz2">osv.tar.bz2</a>                                        16-Dec-2025 18:35     20M
<a href="osv.tar.bz2.asc">osv.tar.bz2.asc</a>                                    14-May-2024 11:59     819
<a href="package2cpe.csv">package2cpe.csv</a>                                    03-Aug-2022 15:57     71K
</pre><hr></body>
</html>
"""


def test_archive_date():
    subject = CSAFClient()
    expected_str = "15-Dec-2025 01:07"
    expected_date = parse(expected_str)
    assert subject.archive_date(example_dir_output) is not None
    assert subject.archive_date(example_dir_output) == expected_date
