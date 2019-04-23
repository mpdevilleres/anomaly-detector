import os
import random
from random import getrandbits
from ipaddress import IPv4Address

import string
from datetime import datetime

from utils import BASE_DIR


def generate_domain():
    min_len = 5
    max_len = 10
    length = random.randint(min_len, max_len)

    #    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length)) + '.com'
    return random.choice(['example.com', 'sample.com', 'another-example.io', 'more-sample.com'])


def generate_ip_address_v4(start=0, end=4294967295):
    """
    Generate a random ip address v4 represented as integer
    0 is 0.0.0.0
    4294967295 is 255.255.255.255
    """
    return random.randint(start, end)


def create_fixture(start_ip='172.0.0.0', end_ip='172.13.255.255'):
    now = datetime.now()

    domain = generate_domain()

    timestamp = datetime.timestamp(now)
    filename = f'{domain}_{now.strftime("%Y%m%d_%H%M%S%f")}.packet'
    client_ip = generate_ip_address_v4()

    content = [timestamp, client_ip, domain]

    for _ in range(0, random.randint(2, 5)):
        start = IPv4Address(start_ip)
        end = IPv4Address(end_ip)
        server_ip = generate_ip_address_v4(int(start), int(end))
        content.append(server_ip)

    content = '\n'.join([str(i) for i in content])

    with open(os.path.join(BASE_DIR, 'packets', filename), 'w') as fn:
        fn.write(content)


if __name__ == '__main__':
    n = 14
    for _ in range(n):
        create_fixture()
