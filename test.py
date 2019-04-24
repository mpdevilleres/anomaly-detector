import os
import unittest
import shutil

from fixture import create_fixtures
from utils import create_lookup, get_packet_files, parse_packet, check_anomaly, build_lookup_dictionary


class TestAnomalyDetector(unittest.TestCase):
    """ Test for Anomaly Detector """

    def setUp(self):
        self.src = 'test_packets'
        if not os.path.exists(self.src):
            os.makedirs(self.src)

        create_fixtures(start_ip='172.13.0.0', end_ip='172.13.255.255', n=50, dst=self.src)

    def tearDown(self):
        shutil.rmtree(self.src)

    def test_get_packet_files(self):
        files = get_packet_files(self.src)
        self.assertEqual(len(files), 50)

    def test_parse_packet(self):
        fn = get_packet_files(self.src)[0]
        packet = parse_packet(fn)

        self.assertTrue(isinstance(packet, dict))
        self.assertTrue('timestamp' in packet.keys())
        self.assertTrue('client_ip' in packet.keys())
        self.assertTrue('domain' in packet.keys())
        self.assertTrue('server_ips' in packet.keys())
        self.assertTrue(isinstance(packet['timestamp'], float))
        self.assertTrue(isinstance(packet['client_ip'], int))
        self.assertTrue(isinstance(packet['domain'], str))
        self.assertTrue(isinstance(packet['server_ips'], list))

    def test_build_lookup_dictionary(self):
        files = get_packet_files(self.src)
        lookups = build_lookup_dictionary(files)

        self.assertTrue(isinstance(lookups, dict))

        keys = list(lookups.keys())
        lookup = lookups[keys[0]]
        self.assertTrue(isinstance(lookup, dict))
        self.assertTrue(isinstance(lookup['cidr'], int))
        self.assertTrue(isinstance(lookup['network_ip'], int))
        self.assertTrue(isinstance(lookup['min_ip'], int))
        self.assertTrue(isinstance(lookup['max_ip'], int))

    def test_create_lookup_01(self):
        # 172.13.118.194, 172.13.176.100, 172.13.94.34, 172.13.179.108
        res = {
            'timestamp': 'any',
            'client_ip': 'any',
            'domain': 'sample.com',
            'server_ips': ["2886563522", "2886578276", "2886557218", "2886579052"]
        }
        result = create_lookup(res)

        # 172.13.0.0, 172.13.0.1, 172.13.255.255
        self.assertEqual(result['cidr'], 16)
        self.assertEqual(result['network_ip'], 2886533120)
        self.assertEqual(result['min_ip'], 2886533121)
        self.assertEqual(result['max_ip'], 2886598654)

    def test_create_lookup_02(self):
        # 10.32.23.95, 10.32.23.5, 10.32.23.51
        res = {
            'timestamp': 'any',
            'client_ip': 'any',
            'domain': 'sample.com',
            'server_ips': ["169875295", "169875205", "169875251"]
        }
        result = create_lookup(res)

        # 10.32.23.0, 10.32.23.1, 10.32.23.254
        self.assertEqual(result['cidr'], 24)
        self.assertEqual(result['network_ip'], 169875200)
        self.assertEqual(result['min_ip'], 169875201)
        self.assertEqual(result['max_ip'], 169875454)

    def test_create_lookup_03(self):
        # 63.32.23.95, 63.31.23.5, 63.34.23.51
        res = {
            'timestamp': 'any',
            'client_ip': 'any',
            'domain': 'sample.com',
            'server_ips': ["1059067743", "1059002117"]
        }
        result = create_lookup(res)

        # 63.0.0.0, 63.0.0.1, 63.255.255.254
        self.assertEqual(result['cidr'], 8)
        self.assertEqual(result['network_ip'], 1056964608)
        self.assertEqual(result['min_ip'], 1056964609)
        self.assertEqual(result['max_ip'], 1073741822)

    def test_check_anomaly_01(self):
        # 63.32.23.95, 63.31.23.5
        res = {
            'timestamp': 'any',
            'client_ip': 'any',
            'domain': 'sample.com',
            'server_ips': [1059067743, 1059002117]
        }
        lookup = create_lookup(res)

        is_anomaly, message = check_anomaly(lookup, res)

        self.assertFalse(is_anomaly)

    def test_check_anomaly_02(self):
        # 63.32.23.95, 63.31.23.5, 63.34.23.51
        res = {
            'timestamp': 'any',
            'client_ip': 1559067743,
            'domain': 'sample.com',
            'server_ips': [1212696648, 1059002117]
        }

        lookup = create_lookup({
            'timestamp': 'any',
            'client_ip': 'any',
            'domain': 'sample.com',
            'server_ips': [1059067743, 1059002117]
        })

        is_anomaly, message = check_anomaly(lookup, res)

        self.assertTrue(is_anomaly)


if __name__ == '__main__':
    unittest.main()
