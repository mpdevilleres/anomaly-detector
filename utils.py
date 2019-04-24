import glob
import logging
import logging.handlers
import os
import collections
import re
from ipaddress import IPv4Address

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

Lookup = collections.namedtuple('Lookup', 'cidr network_ip min_ip max_ip')
Packet = collections.namedtuple('Packet', 'timestamp client_ip domain server_ips')


def init_logger(level):
    """
    initiate a logger to handle stdout and file logging of the system
    note: typical print to console and write to file won't work as they are not thread friendly
    """
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


def get_packet_files(src):
    """
    returns an array or list of all packet files
    """
    if os.path.isabs(src):
        search = os.path.join(src, '*.packet')
    else:
        search = os.path.join(BASE_DIR, src, '*.packet')

    return glob.glob(search)


def parse_packet(file_path):
    """
    parses and returns a dictionary representation of the packets
    eg. {
        'timestamp': 1556071795.61778,
        'client_ip': 4209613797,
        'domain': another-example.io,
        'server_ips': [2885976305, 2886466723]
        }
    """
    with open(file_path, 'r') as fn:
        packet = fn.read().split('\n')

    return {
        'timestamp': float(packet[0]),
        'client_ip': int(packet[1]),
        'domain': packet[2],
        'server_ips': [int(i) for i in packet[3:]]
    }


def create_lookup(res):
    """
    returns a lookup for a single domain
    eg. {
        'cidr': 16,
        'network_ip': 2886533120,
        'min_ip': 2886533121,
        'max_ip': 2886598654
        }
    """
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

    return {
        'cidr': cidr,
        'network_ip': int(IPv4Address(network_ip)),
        'min_ip': int(IPv4Address(network_ip)) + 1,
        'max_ip': int(IPv4Address(network_ip)) + (2 ** (32 - cidr)) - 2,
    }


def build_lookup_dictionary(files):
    """
    return a  lookup dictionary aka lookup table for each domain
    eg. {
        'another-example.io': {'cidr': 16, 'network_ip': 2886533120, 'min_ip': 2886533121, 'max_ip': 2886598654},
        'example.com': {'cidr': 16, 'network_ip': 2886533120, 'min_ip': 2886533121, 'max_ip': 2886598654},
        'more-sample.com': {'cidr': 16, 'network_ip': 2886533120, 'min_ip': 2886533121, 'max_ip': 2886598654},
        'sample.com': {'cidr': 8, 'network_ip': 2885681152, 'min_ip': 2885681153, 'max_ip': 2902458366}
        }
    """
    data = {}
    for fn in files:
        matched = re.search(r'([a-zA-Z0-9_-]+\.[a-z]{2,})', fn)
        domain = matched[0]
        if data.get(domain):
            continue
        data[domain] = fn

    # k = domain
    # v = file to be parse
    return {k: create_lookup(parse_packet(v)) for k, v in data.items()}


def check_anomaly(lookup, packet):
    """
    compare the packet to the lookup table and check if the server_ips are within the subnet
    returns False if it is within range and True with message if its out of range
    """
    for ip in packet['server_ips']:
        if not lookup['min_ip'] <= ip <= lookup['max_ip']:
            return True, f'{packet["domain"]} with IP {IPv4Address(ip)} is an anomaly'
    return False, None
