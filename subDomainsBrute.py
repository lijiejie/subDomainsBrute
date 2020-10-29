#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
    subDomainsBrute 1.4
    A simple and fast sub domains brute tool for pentesters
    my[at]lijiejie.com (http://www.lijiejie.com)
"""

import sys
import multiprocessing
import warnings
warnings.simplefilter("ignore", category=UserWarning)

import time
import signal
import os
import glob
from lib.cmdline import parse_args


if sys.version.split()[0] >= '3.5':
    from lib.scanner_py3 import SubNameBrute
    from lib.common_py3 import load_dns_servers, load_next_sub, print_msg, get_out_file_name, \
        user_abort, wildcard_test, get_sub_file_path
else:
    from lib.scanner_py2 import SubNameBrute
    from lib.common_py2 import load_dns_servers, load_next_sub, print_msg, get_out_file_name, \
        user_abort, wildcard_test, get_sub_file_path


def run_process(*params):
    signal.signal(signal.SIGINT, user_abort)
    s = SubNameBrute(*params)
    s.run()


if __name__ == '__main__':
    options, args = parse_args()
    print('''SubDomainsBrute v1.4  https://github.com/lijiejie/subDomainsBrute''')
    # make tmp dirs
    tmp_dir = 'tmp/%s_%s' % (args[0], int(time.time()))
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    multiprocessing.freeze_support()
    dns_servers = load_dns_servers()
    next_subs = load_next_sub(options)
    scan_count = multiprocessing.Value('i', 0)
    found_count = multiprocessing.Value('i', 0)
    queue_size_array = multiprocessing.Array('i', options.process)

    try:
        print('[+] Run wildcard test')
        if not options.w:
            domain = wildcard_test(args[0], dns_servers)
        else:
            domain = args[0]
        options.file = get_sub_file_path(options)
        print('[+] Start %s scan process' % options.process)
        print('[+] Please wait while scanning ... \n')
        start_time = time.time()
        all_process = []
        for process_num in range(options.process):
            p = multiprocessing.Process(target=run_process,
                                        args=(domain, options, process_num, dns_servers, next_subs,
                                              scan_count, found_count, queue_size_array, tmp_dir)
                                        )
            all_process.append(p)
            p.start()

        char_set = ['\\', '|', '/', '-']
        count = 0
        while all_process:
            for p in all_process:
                if not p.is_alive():
                    all_process.remove(p)
            groups_count = 0
            for c in queue_size_array:
                groups_count += c
            msg = '[%s] %s found, %s scanned in %.1f seconds, %s groups left' % (
                char_set[count % 4], found_count.value, scan_count.value, time.time() - start_time, groups_count)
            print_msg(msg)
            count += 1
            time.sleep(0.3)
    except KeyboardInterrupt as e:
        print('[ERROR] User aborted the scan!')
        for p in all_process:
            p.terminate()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print('[ERROR] %s' % str(e))

    out_file_name = get_out_file_name(domain, options)
    all_domains = set()
    domain_count = 0
    with open(out_file_name, 'w') as f:
        for _file in glob.glob(tmp_dir + '/*.txt'):
            with open(_file, 'r') as tmp_f:
                for domain in tmp_f:
                    if domain not in all_domains:
                        domain_count += 1
                        all_domains.add(domain)       # cname query can result in duplicated domains
                        f.write(domain)

    msg = 'All Done. %s found, %s scanned in %.1f seconds.' % (
        domain_count, scan_count.value, time.time() - start_time)
    print_msg(msg, line_feed=True)
    print('Output file is %s' % out_file_name)
