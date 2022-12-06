import shutil
from distutils import dir_util

import pytest
from pytest import fixture

from vunnel.providers.centos.data import CentOSDataProvider
from vunnel.utils.oval_parser import parse


@pytest.mark.parametrize(
    "mock_data_path",
    [
        "test-fixtures/mock_data_1",
        "test-fixtures/mock_data_2",
    ],
)
def test_parse(tmpdir, helpers, mock_data_path, request):
    mock_data_path = helpers.local_dir(mock_data_path)

    provider = CentOSDataProvider(workspace=tmpdir)
    shutil.copy(mock_data_path, provider.xml_file_path)

    vuln_dict = parse(provider.xml_file_path, provider.config)

    assert vuln_dict is not None
    _, (_, vuln) = vuln_dict.popitem()
    assert isinstance(vuln, dict)
    assert ["Vulnerability"] == list(vuln.keys())

    fixed_in = vuln["Vulnerability"]["FixedIn"][0]

    assert fixed_in is not None
    assert fixed_in["Name"] == "htdig"
    assert fixed_in["Version"] == "2:3.1.6-7.el3"
    # TODO: add more assertions for a full record
