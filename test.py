import unittest

from anomaly_detector import get_reference


class TestAnomalyDetector(unittest.TestCase):
    """ Test for Anomaly Detector """

    def test_get_reference_01(self):
        # 172.13.118.194, 172.13.176.100, 172.13.94.34, 172.13.179.108
        res = {
            'timestamp': 'any',
            'client_ip': 'any',
            'domain': 'sample.com',
            'server_ips': ["2886563522", "2886578276", "2886557218", "2886579052"]
        }
        result = get_reference(res)

        # 172.13.0.0, 172.13.0.1, 172.13.255.255
        self.assertEqual(result['cidr'], 16)
        self.assertEqual(result['network_ip'], 2886533120)
        self.assertEqual(result['min_ip'], 2886533121)
        self.assertEqual(result['max_ip'], 2886598654)

    def test_get_reference_02(self):
        # 10.32.23.95, 10.32.23.5, 10.32.23.51
        res = {
            'timestamp': 'any',
            'client_ip': 'any',
            'domain': 'sample.com',
            'server_ips': ["169875295", "169875205", "169875251"]
        }
        result = get_reference(res)

        # 10.32.23.0, 10.32.23.1, 10.32.23.254
        self.assertEqual(result['cidr'], 24)
        self.assertEqual(result['network_ip'], 169875200)
        self.assertEqual(result['min_ip'], 169875201)
        self.assertEqual(result['max_ip'], 169875454)

    def test_get_reference_03(self):
        # 63.32.23.95, 63.31.23.5, 63.34.23.51
        res = {
            'timestamp': 'any',
            'client_ip': 'any',
            'domain': 'sample.com',
            'server_ips': ["1059067743", "1059002117"]
        }
        result = get_reference(res)

        # 63.0.0.0, 63.0.0.1, 63.255.255.254
        self.assertEqual(result['cidr'], 8)
        self.assertEqual(result['network_ip'], 1056964608)
        self.assertEqual(result['min_ip'], 1056964609)
        self.assertEqual(result['max_ip'], 1073741822)


if __name__ == '__main__':
    unittest.main()
