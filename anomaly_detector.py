import os
import glob
from ipaddress import IPv4Address

import argparse
import threading

import logging
import logging.handlers

from utils import BASE_DIR


def init_logger(level):
    logger = logging.getLogger()
    logger.setLevel(level)
    formatter = logging.Formatter("%(asctime)s - %(threadName)-5s - %(levelname)s - %(message)s")

    fh = logging.handlers.RotatingFileHandler(os.path.join(BASE_DIR, 'output.log'),
                                              maxBytes=(1048576 * 5),  # 5MB
                                              backupCount=7
                                              )
    fh.setLevel(level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)


# http://www.cse.uconn.edu/~vcb5043/MISC/IP%20Intranet.html
# default/common subnets
# class A is 255.0.0.0 /8
# class B is 255.255.0.0 /16
# class C is 255.255.255.0 /24
def get_reference(res):
    ips = [IPv4Address(int(i)) for i in res['server_ips']]
    ips = [[int(x) for x in str(i).split('.')] for i in ips]

    # A.B.C.D 192.168.0.0
    abcd = [set([x[i] for x in ips]) for i in range(0, 4)]
    abcd = [i.pop() if len(i) == 1 else 0 for i in abcd]
    izero = abcd.index(0)
    abcd[izero:] = [0] * len(abcd[izero:])

    network_ip = '.'.join([str(i) for i in abcd])

    subnet_mask = [255 if i > 0 else 0 for i in abcd]
    subnet_mask_bin = '.'.join([f'{i:08b}' for i in subnet_mask])
    cidr = subnet_mask_bin.count('1')

    result = {
        'cidr': cidr,
        'network_ip': int(IPv4Address(network_ip)),
        'min_ip': int(IPv4Address(network_ip)) + 1,
        'max_ip': int(IPv4Address(network_ip)) + (2 ** (32 - cidr)) - 2,
    }
    return result


def get_packet_files(src):
    if os.path.isabs(src):
        search = os.path.join(src, '*.packet')
    else:
        search = os.path.join(BASE_DIR, src, '*.packet')

    return glob.glob(search)


def parse_packet(file_path):
    with open(file_path, 'r') as fn:
        packet = fn.read().split('\n')

    return {
        'timestamp': packet[0],
        'client_ip': packet[1],
        'domain': packet[2],
        'server_ips': [int(i) for i in packet[3:]]
    }


def check_anomaly(lookup, res):
    for ip in res['server_ips']:
        if not lookup['min_ip'] <= ip <= lookup['max_ip']:
            return True, f'{res["domain"]} with IP {IPv4Address(ip)} is an anomaly'
    return False, None


def main(src):
    lookups = {}
    files = get_packet_files(src)

    for i in files:
        res = parse_packet(i)
        if not lookups.get(res['domain']):
            lookups[res['domain']] = get_reference(res)
            continue
        is_anomaly, message = check_anomaly(lookups[res['domain']], res)

        if is_anomaly:
            logging.error(message)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DNS Anomaly Detector')
    parser.add_argument('--threads', metavar='N', type=int,
                        help='number of thread (default: %(default)s)',
                        default=1)
    parser.add_argument('--src', metavar='source_folder', type=str,
                        help='source folder for the dns packet files (default: %(default)s)',
                        default='packets')
    parser.add_argument('--verbose', metavar='level', type=str,
                        help='verbose level [debug, info, error] (default: %(default)s)',
                        choices=['debug', 'info', 'error'],
                        default='error')
    args = parser.parse_args()

    init_logger(args.verbose.upper())

    main(args.src)
