import os
import collections

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

Lookup = collections.namedtuple('Lookup', 'cidr network_ip min_ip max_ip')
Packet = collections.namedtuple('Packet', 'timestamp client_ip domain server_ips')
