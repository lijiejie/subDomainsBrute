#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
    subDomainsBrute 1.3
    A simple and fast sub domains brute tool for pentesters
    my[at]lijiejie.com (http://www.lijiejie.com)
"""

from lib.cmdline import parse_args
import glob
import os
import signal
import time
from concurrent.futures import ProcessPoolExecutor
from itertools import cycle
import sys
import multiprocessing
import nest_asyncio
import asyncio
import warnings
warnings.simplefilter("ignore", category=UserWarning)
nest_asyncio.apply()


global all_done
all_done = False

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


async def async_run(executor, options):
    new_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(new_loop)
    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(executor, run_process,
                                  domain, options, n, dns_servers, next_subs, scan_count, found_count, queue_size_array,
                                  tmp_dir) for n in range(options.process)]
    completed, pending = await asyncio.wait(tasks)
    global all_done
    all_done = True


async def display_status(char=cycle('/|\-')):
    count = 0
    while not all_done:
        groups_count = 0
        for c in queue_size_array:
            groups_count += c
        msg = '[%s] %s found, %s scanned in %.1f seconds, %s groups left' % (
            next(char), found_count.value, scan_count.value, time.time() - start_time, groups_count)
        print_msg(msg)
        count += 1
        await asyncio.sleep(.3)

if __name__ == '__main__':
    options, args = parse_args()
    print('''SubDomainsBrute v1.3  https://github.com/lijiejie/subDomainsBrute''')
    # make tmp dirs
    tmp_dir = 'tmp/%s_%s' % (args[0], int(time.time()))
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    multiprocessing.freeze_support()
    dns_servers = load_dns_servers()
    next_subs = load_next_sub(options)
    scan_count = multiprocessing.Manager().Value('i', 0)
    found_count = multiprocessing.Manager().Value('i', 0)
    queue_size_array = multiprocessing.Manager().Array('i', range(options.process))

    try:
        print('[+] Run wildcard test')
        domain = wildcard_test(args[0], dns_servers)
        options.file = get_sub_file_path(options)
        print('[+] Start %s scan process' % options.process)
        print('[+] Please wait while scanning ... \n')
        start_time = time.time()
        status = asyncio.ensure_future(display_status())
        loop = asyncio.get_event_loop()
        with ProcessPoolExecutor(max_workers=options.process) as executor:
            loop.run_until_complete(asyncio.wait(
                [async_run(executor, options), status]))
        loop.close()

    except KeyboardInterrupt as e:
        print('[ERROR] User aborted the scan!')
        for task in asyncio.Task.all_tasks():
            task.cancel()
        if loop:
            loop.stop()
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
                        # cname query can result in duplicated domains
                        all_domains.add(domain)
                        f.write(domain)

    msg = 'All Done. %s found, %s scanned in %.1f seconds.' % (
        domain_count, scan_count.value, time.time() - start_time)
    print_msg(msg, line_feed=True)
    print('Output file is %s' % out_file_name)
