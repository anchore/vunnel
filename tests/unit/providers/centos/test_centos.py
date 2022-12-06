import logging
import os
import shutil
import unittest

from vunnel.providers.centos.data import CentOSDataProvider
from vunnel.utils.oval_parser import parse


class TestCentOSDataProvider(unittest.TestCase):
    _workspace_ = "/tmp/centos"
    _location_ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    _sample_data_1_ = os.path.join(_location_, "test-fixtures/mock_data_1")
    _sample_data_2_ = os.path.join(_location_, "test-fixtures/mock_data_2")

    # _config_ = None

    @classmethod
    def setUpClass(cls):
        os.makedirs(cls._workspace_, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._workspace_)

    # def test_1_get_latest_sha(self):
    #     provider = driver.CentOSDataProvider(workspace=self._workspace_)
    #     latest = provider._get_sha256()
    #     self.assertIsNotNone(latest, 'Expected a valid result for sha256')
    #
    # def test_2_download(self):
    #     provider = driver.CentOSDataProvider(workspace=self._workspace_)
    #     sha = provider._download(skip_if_exists=False)
    #     self.assertIsNotNone(sha, 'Expected sha of the downloaded file')
    #
    #     sha = provider._download(skip_if_exists=False)
    #     self.assertIsNone(sha, 'Expected download to be no-op')
    #
    #     sha = provider._download(skip_if_exists=True)
    #     self.assertIsNone(sha, 'Expected download to be no-op')
    #
    # def test_3_get(self):
    #     provider = driver.CentOSDataProvider(workspace=self._workspace_)
    #     vuln_dict = provider.get()
    #     self.assertIsNotNone(vuln_dict, 'Expected valid reference')
    #     self.assertIsInstance(vuln_dict, dict, 'Expected a dictionary')
    #     self.assertGreater(len(vuln_dict), 0, 'Expected vulnerability data for main or community')
    #     self.assertTrue(all(map(lambda x: 'Vulnerability' in x[1], vuln_dict.values())))
    #     print('Number of centos vulnerabilities: {}'.format(len(vuln_dict)))

    # def test_parse(self):
    #     provider = driver.CentOSDataProvider(workspace=self._workspace_)
    #     shutil.copy(self._sample_data_1_, provider.xml_file_path)
    #
    #     vuln_dict = driver.parse(provider.xml_file_path, provider.config)
    #     self.assertIsNotNone(vuln_dict, 'Expected valid reference')
    #     self.assertIsInstance(vuln_dict, dict, 'Expected a dictionary')
    #     self.assertGreater(len(vuln_dict), 0, 'Expected vulnerability data for main or community')
    #     self.assertTrue(all(map(lambda x: 'Vulnerability' in x[1], vuln_dict.values())))
    #     print('Number of centos vulnerabilities: {}'.format(len(vuln_dict)))

    def test_parse_1(self):
        provider = CentOSDataProvider(workspace=self._workspace_, logger=logging.getLogger())
        shutil.copy(self._sample_data_1_, provider.xml_file_path)
        vuln_dict = parse(provider.xml_file_path, provider.config)
        self._verify_parser_output(vuln_dict)

    def test_parse_2(self):
        provider = CentOSDataProvider(workspace=self._workspace_, logger=logging.getLogger())
        shutil.copy(self._sample_data_2_, provider.xml_file_path)
        vuln_dict = parse(provider.xml_file_path, provider.config)
        self._verify_parser_output(vuln_dict)

    def _verify_parser_output(self, vuln_dict):
        print("Results: {}".format(vuln_dict))
        self.assertIsNotNone(vuln_dict, "Expected valid reference")
        _, (_, vuln) = vuln_dict.popitem()
        self.assertIsInstance(vuln, dict, "Expected a vulnerability dictionary")
        self.assertEqual(
            ["Vulnerability"],
            list(vuln.keys()),
            "Expected a dictionary with vulnerability as the only key",
        )
        fixed_in = vuln["Vulnerability"]["FixedIn"][0]
        self.assertIsNotNone(fixed_in, "Expected a fixed in record")
        self.assertEqual(fixed_in["Name"], "htdig")
        self.assertEqual(fixed_in["Version"], "2:3.1.6-7.el3")

    # def test_compare(self):
    #     import requests
    #
    #     p1 = driver.CentOSDataProvider(workspace=self._workspace_)
    #     loc1 = os.path.join(TestCentOS._location_, 'com.redhat.rhsa-all.xml')
    #     shutil.copyfile(loc1, p1.xml_file_path)
    #
    #     p2 = driver.CentOSDataProvider(workspace=self._workspace_)
    #     r = requests.get('https://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml', stream=True)
    #     with open(p2.xml_file_path, 'wb') as fp:
    #         for chunk in r.iter_content(chunk_size=1024):
    #             fp.write(chunk)
    #
    #     ret1 = driver.parse(p1.xml_file_path, p1.config)
    #     ret2 = driver.parse(p2.xml_file_path, p2.config)
    #
    #     for tup1, tup2 in ret1.items():
    #         if tup1 not in ret2:
    #             print('{} not found in new data')
    #             continue
    #
    #         payload1 = tup2[1]
    #         payload2 = ret2[tup1][1]
    #
    #         if payload1 != payload2:
    #             print('Payloads different for {}'.format(tup1))
