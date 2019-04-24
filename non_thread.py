"""
This is a single thread execution
"""
import argparse
import logging

from utils import init_logger, get_packet_files, parse_packet, \
    build_lookup_dictionary, check_anomaly


def worker(fn, lookups):
    res = parse_packet(fn)
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
    files = get_packet_files(args.src)
    lookups = build_lookup_dictionary(files)
    for i in files:
        worker(i, lookups)
