import unittest
import os
from pathlib import Path

from dap_py import DAP

cert_path = ""


def main():
    global cert_path
    default_path = Path(os.path.dirname(__file__)).parent / "certs/.a2e.energy.gov.cert"
    if "DAP_CERT_DIR" not in os.environ:
        print(
            f"Environment variable 'DAP_CERT_DIR' is not set. Looking for a certificate "
            f"named .a2e.energy.gov.cert in the default directory {default_path}..."
        )
        if not default_path.is_file():
            print(
                "Certificate not found. Any tests that rely on certificate authentication will fail."
            )
        else:
            print(f"Certificate found! {default_path}")
            cert_path = default_path
    else:
        print(f"Looking for a certificate in {os.getenv('DAP_CERT_DIR')}...")
        test_path = Path(os.getenv("DAP_CERT_DIR")) / ".a2e.energy.gov.cert"
        if not test_path.is_file():
            print(
                f"There is no file named '.a2e.energy.gov.cert' in {os.getenv('DAP_CERT_DIR')} "
                f"Any tests that rely on certificate authentication will fail."
            )
        else:
            print(f"Certificate found! {test_path}")
            cert_path = test_path

    unittest.main()


class TestDap(unittest.TestCase):
    def test_create_a2e(self):
        a2e = DAP("a2e.energy.gov", cert_path)
        print("Test create a2e passed.")

    def test_search_inventory_lidar_z04_a0(self):
        a2e = DAP("a2e.energy.gov", cert_path)
        files_check = [
            {
                "size": 14987484,
                "data_time": "000000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "nc",
                "name_attr": "9afdd1c12a.1/wfip2/lidar.z04.a0.20151001.000000.beamdata_ppi.nc",
                "Dataset": "wfip2/lidar.z04.a0",
                "date_time": "20151001000000",
                "ext1": "beamdata_ppi",
                "class": "lidar",
                "instance": "z04",
                "signature": "9fc8e1f4548ffecb22cc9144cb0d5eb041aaa3f5d5db5038f088f9a134df1b71",
                "received": 1459384488,
                "iteration": 1,
                "level": "a0",
                "latest": True,
                "data_date": "20151001",
                "Filename": "9afdd1c12a.1/wfip2/lidar.z04.a0.20151001.000000.beamdata_ppi.nc",
            },
            {
                "size": 8020932,
                "data_time": "000000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "nc",
                "name_attr": "85c4cbe232.1/wfip2/lidar.z04.a0.20151001.000000.beamdata_stare.nc",
                "Dataset": "wfip2/lidar.z04.a0",
                "date_time": "20151001000000",
                "ext1": "beamdata_stare",
                "class": "lidar",
                "instance": "z04",
                "signature": "02d8729819bf23b7887bb3e27de6286a5e0237a0dc7e1e7c3025a569173083d6",
                "received": 1459384523,
                "iteration": 1,
                "level": "a0",
                "latest": True,
                "data_date": "20151001",
                "Filename": "85c4cbe232.1/wfip2/lidar.z04.a0.20151001.000000.beamdata_stare.nc",
            },
            {
                "size": 5282868,
                "data_time": "010000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "nc",
                "name_attr": "4329ca64b5.1/wfip2/lidar.z04.a0.20151001.010000.beamdata_stare.nc",
                "Dataset": "wfip2/lidar.z04.a0",
                "date_time": "20151001010000",
                "ext1": "beamdata_stare",
                "class": "lidar",
                "instance": "z04",
                "signature": "e205f66ea983dbbfc3ed4231c4d66ec2ea76fbef06639799895e82db428e30e6",
                "received": 1459384621,
                "iteration": 1,
                "level": "a0",
                "latest": True,
                "data_date": "20151001",
                "Filename": "4329ca64b5.1/wfip2/lidar.z04.a0.20151001.010000.beamdata_stare.nc",
            },
            {
                "size": 19337364,
                "data_time": "010000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "nc",
                "name_attr": "ee95b541db.1/wfip2/lidar.z04.a0.20151001.010000.beamdata_ppi.nc",
                "Dataset": "wfip2/lidar.z04.a0",
                "date_time": "20151001010000",
                "ext1": "beamdata_ppi",
                "class": "lidar",
                "instance": "z04",
                "signature": "625cbcfe640b9c8e01c4b5e82d9e38cb08b902a8aac150c817423d3a4f83dc4e",
                "received": 1459384597,
                "iteration": 1,
                "level": "a0",
                "latest": True,
                "data_date": "20151001",
                "Filename": "ee95b541db.1/wfip2/lidar.z04.a0.20151001.010000.beamdata_ppi.nc",
            },
            {
                "size": 19310388,
                "data_time": "020000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "nc",
                "name_attr": "4a8cab06df.1/wfip2/lidar.z04.a0.20151001.020000.beamdata_ppi.nc",
                "Dataset": "wfip2/lidar.z04.a0",
                "date_time": "20151001020000",
                "ext1": "beamdata_ppi",
                "class": "lidar",
                "instance": "z04",
                "signature": "f7df03b0c7b91c4c820c292b246c5faa79083763c027d42bd916bec4b57908c5",
                "received": 1459384695,
                "iteration": 1,
                "level": "a0",
                "latest": True,
                "data_date": "20151001",
                "Filename": "4a8cab06df.1/wfip2/lidar.z04.a0.20151001.020000.beamdata_ppi.nc",
            },
            {
                "size": 5019852,
                "data_time": "020000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "nc",
                "name_attr": "e63623a0a2.1/wfip2/lidar.z04.a0.20151001.020000.beamdata_stare.nc",
                "Dataset": "wfip2/lidar.z04.a0",
                "date_time": "20151001020000",
                "ext1": "beamdata_stare",
                "class": "lidar",
                "instance": "z04",
                "signature": "57e044998f922756879a72c5102b69147abf1123eb0218ae2c3f1cf5a502bce1",
                "received": 1459384719,
                "iteration": 1,
                "level": "a0",
                "latest": True,
                "data_date": "20151001",
                "Filename": "e63623a0a2.1/wfip2/lidar.z04.a0.20151001.020000.beamdata_stare.nc",
            },
        ]
        expected_len = len(files_check)

        filter = {
            "Dataset": "wfip2/lidar.z04.a0",
            "date_time": {"between": ["20151001000000", "20151001020000"]},
            "file_type": "nc",
        }

        file_names = a2e.search(filter, table="inventory")

        self.assertEqual(
            len(file_names),
            expected_len,
            f"Search did not return the expected number of files: {expected_len}",
        )
        self.assertEqual(file_names, files_check, "Search returned unexpected files")
        print("Test search inventory lidar.z04.a0 passed.")

    def test_search_inventory_sodar_z15_00(self):
        a2e = DAP("a2e.energy.gov", cert_path)
        files_check = [
            {
                "size": 4921,
                "data_time": "190700",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "a6e695b340.0/wfip2/sodar.z15.00.20160314.190700.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314190700",
                "class": "sodar",
                "instance": "z15",
                "signature": "a39b52b957bdd75b0dcc81430031cc8cb65afbc71d9ecac58a8a34de51a4bb8e",
                "received": 1458838374,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "a6e695b340.0/wfip2/sodar.z15.00.20160314.190700.txt",
            },
            {
                "size": 4921,
                "data_time": "191500",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "aa8ecb9f88.0/wfip2/sodar.z15.00.20160314.191500.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314191500",
                "class": "sodar",
                "instance": "z15",
                "signature": "7d536743e905337610d2832dfeb3621277da6a4db8db068cab2f7e61e58952bc",
                "received": 1458838375,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "aa8ecb9f88.0/wfip2/sodar.z15.00.20160314.191500.txt",
            },
            {
                "size": 4921,
                "data_time": "193000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "5f9cb3bae3.0/wfip2/sodar.z15.00.20160314.193000.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314193000",
                "class": "sodar",
                "instance": "z15",
                "signature": "416fbc784f0f82aeae8de80c78064f396144973852f497a3cd61e957b1b52d32",
                "received": 1458838375,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "5f9cb3bae3.0/wfip2/sodar.z15.00.20160314.193000.txt",
            },
            {
                "size": 4921,
                "data_time": "194500",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "9706d8ed85.0/wfip2/sodar.z15.00.20160314.194500.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314194500",
                "class": "sodar",
                "instance": "z15",
                "signature": "1edf1d07163a9dc8b3b880a50de45860559c78bdd987b1aa33e3c1371edb26e0",
                "received": 1458838375,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "9706d8ed85.0/wfip2/sodar.z15.00.20160314.194500.txt",
            },
            {
                "size": 4921,
                "data_time": "200000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "4e40d6c05a.0/wfip2/sodar.z15.00.20160314.200000.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314200000",
                "class": "sodar",
                "instance": "z15",
                "signature": "d26a9b7aad306952c89836a279091286a80dd5829ca42dda7eed801dc38d5f17",
                "received": 1458838376,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "4e40d6c05a.0/wfip2/sodar.z15.00.20160314.200000.txt",
            },
            {
                "size": 4921,
                "data_time": "201500",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "8bdb193860.0/wfip2/sodar.z15.00.20160314.201500.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314201500",
                "class": "sodar",
                "instance": "z15",
                "signature": "c7ab0a30bbd7888b543c3ed46214f874feb1e6555e2b3f09bc4b71e3d286db4f",
                "received": 1458838376,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "8bdb193860.0/wfip2/sodar.z15.00.20160314.201500.txt",
            },
            {
                "size": 4921,
                "data_time": "203000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "621e2655f3.0/wfip2/sodar.z15.00.20160314.203000.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314203000",
                "class": "sodar",
                "instance": "z15",
                "signature": "68d4509b6ae9da1951f8ad8bb1fa3c9e2c7958a14c3400c6df624a1587c0e321",
                "received": 1458838376,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "621e2655f3.0/wfip2/sodar.z15.00.20160314.203000.txt",
            },
            {
                "size": 4921,
                "data_time": "204500",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "92d51c214a.0/wfip2/sodar.z15.00.20160314.204500.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314204500",
                "class": "sodar",
                "instance": "z15",
                "signature": "9ca88d7bfdb622f44d7ca3ae8343825a1386a1f28019f44399be883d929527e2",
                "received": 1458838377,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "92d51c214a.0/wfip2/sodar.z15.00.20160314.204500.txt",
            },
            {
                "size": 4921,
                "data_time": "210000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "1ea4db5db7.0/wfip2/sodar.z15.00.20160314.210000.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314210000",
                "class": "sodar",
                "instance": "z15",
                "signature": "fee6f2cfddf963fc1ee1beef96d88306631caed85dd7748da7ec65e913ec1bb8",
                "received": 1458838377,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "1ea4db5db7.0/wfip2/sodar.z15.00.20160314.210000.txt",
            },
            {
                "size": 4921,
                "data_time": "211500",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "25db6a6e89.0/wfip2/sodar.z15.00.20160314.211500.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314211500",
                "class": "sodar",
                "instance": "z15",
                "signature": "da1ad9da6ee31944042a3b8dc5e6f4620a5bef98b6ba8089fa5803f6f6a72d41",
                "received": 1458838377,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "25db6a6e89.0/wfip2/sodar.z15.00.20160314.211500.txt",
            },
            {
                "size": 4921,
                "data_time": "213000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "c49c9d59c8.0/wfip2/sodar.z15.00.20160314.213000.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314213000",
                "class": "sodar",
                "instance": "z15",
                "signature": "ac9995f8f4b8438fd14d257b97b18470b5b968ed7290c79a09bae4b677d3ffed",
                "received": 1458838378,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "c49c9d59c8.0/wfip2/sodar.z15.00.20160314.213000.txt",
            },
            {
                "size": 4921,
                "data_time": "214500",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "6c113fb502.0/wfip2/sodar.z15.00.20160314.214500.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314214500",
                "class": "sodar",
                "instance": "z15",
                "signature": "be96cf3ea7eee4ddfb8a4b2714be0867a2d2a4f74f0ed7a496d80d7222dc440b",
                "received": 1458838378,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "6c113fb502.0/wfip2/sodar.z15.00.20160314.214500.txt",
            },
            {
                "size": 4921,
                "data_time": "220000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "44649fc1b0.0/wfip2/sodar.z15.00.20160314.220000.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314220000",
                "class": "sodar",
                "instance": "z15",
                "signature": "b692ab17f231c70f763d931b2d2ac64aa767d4eee3be18a5d8db9d1563509515",
                "received": 1458838378,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "44649fc1b0.0/wfip2/sodar.z15.00.20160314.220000.txt",
            },
            {
                "size": 4921,
                "data_time": "221500",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "a62b42e430.0/wfip2/sodar.z15.00.20160314.221500.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314221500",
                "class": "sodar",
                "instance": "z15",
                "signature": "9787eda0f7682976057c9f110d57d624fb6f956917582e0600ac27d7c76385d5",
                "received": 1458838379,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "a62b42e430.0/wfip2/sodar.z15.00.20160314.221500.txt",
            },
            {
                "size": 4921,
                "data_time": "223000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "71c15c5c68.0/wfip2/sodar.z15.00.20160314.223000.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314223000",
                "class": "sodar",
                "instance": "z15",
                "signature": "a3ee6b14d33e267b97cf2af9a6190fd74c7ca142fdce4970f6a8b596785f34e4",
                "received": 1458838379,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "71c15c5c68.0/wfip2/sodar.z15.00.20160314.223000.txt",
            },
            {
                "size": 4921,
                "data_time": "224500",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "449685695a.0/wfip2/sodar.z15.00.20160314.224500.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314224500",
                "class": "sodar",
                "instance": "z15",
                "signature": "1b131eed3c8e49dfe4e7e21f138fc552600a9ef191fa1db9a942cd7c7529fc75",
                "received": 1458838379,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "449685695a.0/wfip2/sodar.z15.00.20160314.224500.txt",
            },
            {
                "size": 4921,
                "data_time": "230000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "1f0760aa8d.0/wfip2/sodar.z15.00.20160314.230000.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314230000",
                "class": "sodar",
                "instance": "z15",
                "signature": "3516d527f3a5a8a2f40f9538af7b8ff077d24bbafb7ae5adba03e272128f12a4",
                "received": 1458838380,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "1f0760aa8d.0/wfip2/sodar.z15.00.20160314.230000.txt",
            },
            {
                "size": 4921,
                "data_time": "231500",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "784dd73a7e.0/wfip2/sodar.z15.00.20160314.231500.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314231500",
                "class": "sodar",
                "instance": "z15",
                "signature": "3a1fde2a2538736739af56ab6155ec4fcf439c7aaff71d0a9e4848a1f8e19c02",
                "received": 1458838380,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "784dd73a7e.0/wfip2/sodar.z15.00.20160314.231500.txt",
            },
            {
                "size": 4921,
                "data_time": "233000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "124a285655.0/wfip2/sodar.z15.00.20160314.233000.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314233000",
                "class": "sodar",
                "instance": "z15",
                "signature": "1b68e0e2ae4f3745710a263498a6db475988b5f40137d3549d45854f17efb542",
                "received": 1458838381,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "124a285655.0/wfip2/sodar.z15.00.20160314.233000.txt",
            },
            {
                "size": 4921,
                "data_time": "234500",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "1d239612af.1/wfip2/sodar.z15.00.20160314.234500.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160314234500",
                "class": "sodar",
                "instance": "z15",
                "signature": "97db307f7f57b66406eb729de18a6e92e57664f63cc1eb354c0913c9ad92c74e",
                "received": 1458838381,
                "iteration": 1,
                "level": "00",
                "latest": True,
                "data_date": "20160314",
                "Filename": "1d239612af.1/wfip2/sodar.z15.00.20160314.234500.txt",
            },
            {
                "size": 4921,
                "data_time": "000000",
                "repo_uri": "https://s3-us-west-2.amazonaws.com/data-a2e",
                "file_type": "txt",
                "name_attr": "c856bb6e33.0/wfip2/sodar.z15.00.20160315.000000.txt",
                "Dataset": "wfip2/sodar.z15.00",
                "date_time": "20160315000000",
                "class": "sodar",
                "instance": "z15",
                "signature": "b5e8d4ab0d050c45979ba92e0fdf0015f270027d5fced8dbf99cecb6a75210a0",
                "received": 1458845753,
                "iteration": 0,
                "level": "00",
                "latest": True,
                "data_date": "20160315",
                "Filename": "c856bb6e33.0/wfip2/sodar.z15.00.20160315.000000.txt",
            },
        ]
        expected_len = len(files_check)

        filter = {
            "Dataset": "wfip2/sodar.z15.00",
            "date_time": {"between": ["20160314000000", "20160315000000"]},
            "file_type": "txt",
        }

        file_names = a2e.search(filter, table="inventory")

        self.assertEqual(
            len(file_names),
            expected_len,
            f"Search did not return the expected number of files: {expected_len}",
        )
        self.assertEqual(file_names, files_check, "Search returned unexpected files")

        print("Test search inventory sodar.z15.00 passed.")

    def test_search_inventory_buoy_z05_00(self):
        a2e = DAP("a2e.energy.gov", cert_path)
        files_check = [
            {
                "size": 6861,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "8edc88e5ed.1/buoy/buoy.z05.00.20201015.000000.gill.csv",
                "file_type": "csv",
                "date_time": "20201015000000",
                "ext1": "gill",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201015.000000.gill.csv",
                "signature": "bf95524ac2052ef23b143a9da0bf9780fbe8ddf42ad5dff925cbad90c4ec260a",
                "data-level": "00",
                "received": 1639086880,
                "iteration": 1,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201015",
                "Filename": "8edc88e5ed.1/buoy/buoy.z05.00.20201015.000000.gill.csv",
            },
            {
                "size": 5183,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "8464537e1c.0/buoy/buoy.z05.00.20201015.000000.conductivity.csv",
                "file_type": "csv",
                "date_time": "20201015000000",
                "ext1": "conductivity",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201015.000000.conductivity.csv",
                "signature": "76db53706cfdb8bf3a5a82cc30a7ed720dbe108eba74f603072a931b2c72592e",
                "data-level": "00",
                "received": 1602825490,
                "iteration": 0,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201015",
                "Filename": "8464537e1c.0/buoy/buoy.z05.00.20201015.000000.conductivity.csv",
            },
            {
                "size": 6807,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "6ee5a62a6e.1/buoy/buoy.z05.00.20201016.000000.gill.csv",
                "file_type": "csv",
                "date_time": "20201016000000",
                "ext1": "gill",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201016.000000.gill.csv",
                "signature": "4ef5cb57c42b93f4945d19bfef44d2c219711c149b526be966cd1498d42eb990",
                "data-level": "00",
                "received": 1639086879,
                "iteration": 1,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201016",
                "Filename": "6ee5a62a6e.1/buoy/buoy.z05.00.20201016.000000.gill.csv",
            },
            {
                "size": 4999,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "6d773d4010.0/buoy/buoy.z05.00.20201016.000000.conductivity.csv",
                "file_type": "csv",
                "date_time": "20201016000000",
                "ext1": "conductivity",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201016.000000.conductivity.csv",
                "signature": "3f770b589414c424ac02811468be74679fc777c43d44414c7a1bb350c758834a",
                "data-level": "00",
                "received": 1602911901,
                "iteration": 0,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201016",
                "Filename": "6d773d4010.0/buoy/buoy.z05.00.20201016.000000.conductivity.csv",
            },
            {
                "size": 5094,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "e752296074.0/buoy/buoy.z05.00.20201017.000000.conductivity.csv",
                "file_type": "csv",
                "date_time": "20201017000000",
                "ext1": "conductivity",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201017.000000.conductivity.csv",
                "signature": "6f947beb37126938c0886f84e88abc6ec80c690c8f2f9ef0429f9d5a39379215",
                "data-level": "00",
                "received": 1602998285,
                "iteration": 0,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201017",
                "Filename": "e752296074.0/buoy/buoy.z05.00.20201017.000000.conductivity.csv",
            },
            {
                "size": 6806,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "8c6642def4.1/buoy/buoy.z05.00.20201017.000000.gill.csv",
                "file_type": "csv",
                "date_time": "20201017000000",
                "ext1": "gill",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201017.000000.gill.csv",
                "signature": "6fc4d275aee86dca60a4b00eaf7ab9c771b7cc0ce945a725ca8189fe6aa40388",
                "data-level": "00",
                "received": 1639086881,
                "iteration": 1,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201017",
                "Filename": "8c6642def4.1/buoy/buoy.z05.00.20201017.000000.gill.csv",
            },
            {
                "size": 6868,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "33f5c2a8b3.1/buoy/buoy.z05.00.20201018.000000.gill.csv",
                "file_type": "csv",
                "date_time": "20201018000000",
                "ext1": "gill",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201018.000000.gill.csv",
                "signature": "47daf87f1510c95edf4d2f35aaebdce7eea42fa6b39e130c5ae82f48dccb0fa6",
                "data-level": "00",
                "received": 1639086878,
                "iteration": 1,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201018",
                "Filename": "33f5c2a8b3.1/buoy/buoy.z05.00.20201018.000000.gill.csv",
            },
            {
                "size": 5064,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "9ecb5e5efc.0/buoy/buoy.z05.00.20201018.000000.conductivity.csv",
                "file_type": "csv",
                "date_time": "20201018000000",
                "ext1": "conductivity",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201018.000000.conductivity.csv",
                "signature": "f200e12613e2d9a8dd49417912db526d29012dd33356f8515745bed38f74f78a",
                "data-level": "00",
                "received": 1603084690,
                "iteration": 0,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201018",
                "Filename": "9ecb5e5efc.0/buoy/buoy.z05.00.20201018.000000.conductivity.csv",
            },
            {
                "size": 6763,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "5b76dae2f6.1/buoy/buoy.z05.00.20201019.000000.gill.csv",
                "file_type": "csv",
                "date_time": "20201019000000",
                "ext1": "gill",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201019.000000.gill.csv",
                "signature": "7898ceaed7117f7d644811dcfd42cd57caabf8e768fe4f93ef4254bc610586d4",
                "data-level": "00",
                "received": 1639086881,
                "iteration": 1,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201019",
                "Filename": "5b76dae2f6.1/buoy/buoy.z05.00.20201019.000000.gill.csv",
            },
            {
                "size": 5044,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "a568bf4fa7.0/buoy/buoy.z05.00.20201019.000000.conductivity.csv",
                "file_type": "csv",
                "date_time": "20201019000000",
                "ext1": "conductivity",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201019.000000.conductivity.csv",
                "signature": "ebf0c0f13c222a0b1573b9f9cc48b6d36886deabd5308c77c40216a45fb811e4",
                "data-level": "00",
                "received": 1603171115,
                "iteration": 0,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201019",
                "Filename": "a568bf4fa7.0/buoy/buoy.z05.00.20201019.000000.conductivity.csv",
            },
            {
                "size": 6874,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "9a9725829a.1/buoy/buoy.z05.00.20201020.000000.gill.csv",
                "file_type": "csv",
                "date_time": "20201020000000",
                "ext1": "gill",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201020.000000.gill.csv",
                "signature": "7d1134c86ae1a9940d0953416530623421ae592d0c96751c4ff6cd606343fb06",
                "data-level": "00",
                "received": 1639086881,
                "iteration": 1,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201020",
                "Filename": "9a9725829a.1/buoy/buoy.z05.00.20201020.000000.gill.csv",
            },
            {
                "size": 5059,
                "data_time": "000000",
                "repo_uri": "https://s3.us-west-2.amazonaws.com/data-a2e",
                "Dataset": "buoy/buoy.z05.00",
                "name_attr": "30c2b7cd7b.0/buoy/buoy.z05.00.20201020.000000.conductivity.csv",
                "file_type": "csv",
                "date_time": "20201020000000",
                "ext1": "conductivity",
                "instance": "z05",
                "name": "buoy/buoy.z05.00.20201020.000000.conductivity.csv",
                "signature": "d33b47bb3a6d94bf19c35aa705f0b2fb0f249abff5e2e54f5de2294024fd0e01",
                "data-level": "00",
                "received": 1603257514,
                "iteration": 0,
                "latest": True,
                "instrument": "buoy",
                "data_date": "20201020",
                "Filename": "30c2b7cd7b.0/buoy/buoy.z05.00.20201020.000000.conductivity.csv",
            },
        ]

        expected_len = len(files_check)

        filter = {
            "Dataset": "buoy/buoy.z05.00",
            "date_time": {"between": ["20201015000000", "20201020000000"]},
            "file_type": "csv",
            "ext1": ["conductivity", "gill"],
        }

        file_names = a2e.search(filter, table="inventory")
        self.assertEqual(
            len(file_names),
            expected_len,
            f"Search did not return the expected number of files: {expected_len}",
        )
        self.assertEqual(file_names, files_check, "Search returned unexpected files")

        print("Test search inventory buoy.z05.00 passed.")

    def test_search_stats_awaken_aml_lidar_z02_00(self):
        a2e = DAP("a2e.energy.gov", cert_path)
        result_check = {
            "name": "InvStats",
            "stats": {
                "range": None,
                "days": ["20140805-20140809"],
                "count": 5,
                "countdev": 0,
                "size": 5931427,
                "sizedev": 163802,
            },
        }

        filter = {
            "Dataset": "tap/arm.lidar.nsa.c1.c1",
            "date_time": {"between": ["20140805000000", "20140809000000"]},
        }

        result = a2e.search(filter, table="stats")

        self.assertEqual(result, result_check, "Stats search returned an unexpected result")
        print("Test search stats tap arm.lidar.nsa.c1.c1 passed.")

    def test_download(self):
        a2e = DAP("a2e.energy.gov", cert_path, confirm_downloads=False)
        filter = {
            "Dataset": "wfip2/lidar.z04.a0",
            "date_time": {"between": ["20151014000000", "20151014010000"]},
            "file_type": "nc",
        }

        # download via a list of files
        file_names = a2e.search(filter, table="inventory")

        files = a2e.download_files(file_names, replace=True)

        self.assertEqual(
            4,
            len(files),
            "An unexpected number of files were downloaded from a list of files.",
        )

        for f in files:
            if not os.path.exists(f):
                raise AssertionError(f"Supposedly downloaded file does not exist: {f}")

        # download via a search
        files = a2e.download_search(filter, replace=True)

        self.assertEqual(
            4,
            len(files),
            "An unexpected number of files were downloaded when downloading via search.",
        )

        for f in files:
            if not os.path.exists(f):
                raise AssertionError(f"Supposedly downloaded file does not exist: {f}")

        # download by placing an order
        files = a2e.download_with_order(filter, replace=True)

        self.assertEqual(
            4,
            len(files),
            "An unexpected number of files were downloaded via placing an order.",
        )

        for f in files:
            if not os.path.exists(f):
                raise AssertionError(f"Supposedly downloaded file does not exist: {f}")

        print("Test download passed.")


if __name__ == "__main__":
    main()
