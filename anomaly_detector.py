import argparse
import logging
import threading
from queue import Queue

from utils import init_logger, get_packet_files, parse_packet, \
    build_lookup_dictionary, check_anomaly


def worker(lookups):
    """
    This function serves as the thread that execute a task from the queue
    """
    while True:
        fn = q.get()
        res = parse_packet(fn)
        is_anomaly, message = check_anomaly(lookups[res['domain']], res)
        if is_anomaly:
            logging.error(message)

        q.task_done()


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

    # Step 1 parse the arguments from the console
    args = parser.parse_args()

    # Step 2 initiate the required parameters
    init_logger(args.verbose.upper())
    files = get_packet_files(args.src)
    lookups = build_lookup_dictionary(files)

    # Step 3 create a Queue/Tasks of all packets
    q = Queue()
    for fn in files:
        q.put(fn)

    # Step 4 create a specified number of threads and and pass the worker
    for i in range(args.threads):
        t = threading.Thread(target=worker, args=(lookups,))
        t.daemon = True
        t.start()

    # Step 5 wait for all the task to be finished before closing the program
    q.join()
