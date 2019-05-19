#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
    subDomainsBrute 1.2
    A simple and fast sub domains brute tool for pentesters
    my[at]lijiejie.com (http://www.lijiejie.com)
"""

import multiprocessing
import warnings
warnings.simplefilter("ignore", category=UserWarning)
import gevent
from gevent import monkey
monkey.patch_all()
from gevent.queue import PriorityQueue
from gevent.lock import RLock
import re
import dns.resolver
import time
import signal
import os
import glob
from lib.cmdline import parse_args
from lib.common import is_intranet, load_dns_servers, load_next_sub, print_msg, get_out_file_name, \
    user_abort


class SubNameBrute(object):
    def __init__(self, *params):
        self.domain, self.options, self.process_num, self.dns_servers, self.next_subs, \
            self.scan_count, self.found_count, self.queue_size_array, tmp_dir = params
        self.dns_count = len(self.dns_servers)
        self.scan_count_local = 0
        self.found_count_local = 0
        self.resolvers = [dns.resolver.Resolver(configure=False) for _ in range(self.options.threads)]
        for r in self.resolvers:
            r.lifetime = r.timeout = 10.0
        self.queue = PriorityQueue()
        self.priority = 0
        self.ip_dict = {}
        self.found_subs = set()
        self.timeout_subs = {}
        self.count_time = time.time()
        self.outfile = open('%s/%s_part_%s.txt' % (tmp_dir, self.domain, self.process_num), 'w')
        self.normal_names_set = set()
        self.load_sub_names()
        self.lock = RLock()

    def load_sub_names(self):
        normal_lines = []
        wildcard_lines = []
        wildcard_set = set()
        regex_list = []
        lines = set()
        with open(self.options.file) as inFile:
            for line in inFile.xreadlines():
                sub = line.strip()
                if not sub or sub in lines:
                    continue
                lines.add(sub)

                brace_count = sub.count('{')
                if brace_count > 0:
                    wildcard_lines.append((brace_count, sub))
                    sub = sub.replace('{alphnum}', '[a-z0-9]')
                    sub = sub.replace('{alpha}', '[a-z]')
                    sub = sub.replace('{num}', '[0-9]')
                    if sub not in wildcard_set:
                        wildcard_set.add(sub)
                        regex_list.append('^' + sub + '$')
                else:
                    normal_lines.append(sub)
                    self.normal_names_set.add(sub)

        if regex_list:
            pattern = '|'.join(regex_list)
            _regex = re.compile(pattern)
            for line in normal_lines:
                if _regex.search(line):
                    normal_lines.remove(line)

        for _ in normal_lines[self.process_num::self.options.process]:
            self.queue.put((0, _))    # priority set to 0
        for _ in wildcard_lines[self.process_num::self.options.process]:
            self.queue.put(_)

    def scan(self, j):
        self.resolvers[j].nameservers = [self.dns_servers[j % self.dns_count]] + self.dns_servers

        while True:
            try:
                self.lock.acquire()
                if time.time() - self.count_time > 1.0:
                    self.scan_count.value += self.scan_count_local
                    self.scan_count_local = 0
                    self.queue_size_array[self.process_num] = self.queue.qsize()
                    if self.found_count_local:
                        self.found_count.value += self.found_count_local
                        self.found_count_local = 0
                    self.count_time = time.time()
                self.lock.release()
                brace_count, sub = self.queue.get(timeout=3.0)
                if brace_count > 0:
                    brace_count -= 1
                    if sub.find('{next_sub}') >= 0:
                        for _ in self.next_subs:
                            self.queue.put((0, sub.replace('{next_sub}', _)))
                    if sub.find('{alphnum}') >= 0:
                        for _ in 'abcdefghijklmnopqrstuvwxyz0123456789':
                            self.queue.put((brace_count, sub.replace('{alphnum}', _, 1)))
                    elif sub.find('{alpha}') >= 0:
                        for _ in 'abcdefghijklmnopqrstuvwxyz':
                            self.queue.put((brace_count, sub.replace('{alpha}', _, 1)))
                    elif sub.find('{num}') >= 0:
                        for _ in '0123456789':
                            self.queue.put((brace_count, sub.replace('{num}', _, 1)))
                    continue
            except gevent.queue.Empty as e:
                break

            try:

                if sub in self.found_subs:
                    continue

                self.scan_count_local += 1
                cur_domain = sub + '.' + self.domain
                answers = self.resolvers[j].query(cur_domain)

                if answers:
                    self.found_subs.add(sub)
                    ips = ', '.join(sorted([answer.address for answer in answers]))
                    if ips in ['1.1.1.1', '127.0.0.1', '0.0.0.0', '0.0.0.1']:
                        continue
                    if self.options.i and is_intranet(answers[0].address):
                        continue

                    try:
                        self.scan_count_local += 1
                        answers = self.resolvers[j].query(cur_domain, 'cname')
                        cname = answers[0].target.to_unicode().rstrip('.')
                        if cname.endswith(self.domain) and cname not in self.found_subs:
                            cname_sub = cname[:len(cname) - len(self.domain) - 1]    # new sub
                            if cname_sub not in self.normal_names_set:
                                self.found_subs.add(cname)
                                self.queue.put((0, cname_sub))
                    except Exception as e:
                        pass

                    first_level_sub = sub.split('.')[-1]
                    if (first_level_sub, ips) not in self.ip_dict:
                        self.ip_dict[(first_level_sub, ips)] = 1
                    else:
                        self.ip_dict[(first_level_sub, ips)] += 1
                        if self.ip_dict[(first_level_sub, ips)] > 30:
                            continue

                    self.found_count_local += 1

                    self.outfile.write(cur_domain.ljust(30) + '\t' + ips + '\n')
                    self.outfile.flush()
                    try:
                        self.scan_count_local += 1
                        self.resolvers[j].query('lijiejie-test-not-existed.' + cur_domain)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                        if self.queue.qsize() < 10000:
                            for _ in self.next_subs:
                                self.queue.put((0, _ + '.' + sub))
                        else:
                            self.queue.put((1, '{next_sub}.' + sub))
                    except Exception as e:
                        pass

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                pass
            except dns.resolver.NoNameservers as e:
                self.queue.put((0, sub))    # Retry
            except dns.exception.Timeout as e:
                self.timeout_subs[sub] = self.timeout_subs.get(sub, 0) + 1
                if self.timeout_subs[sub] <= 2:
                    self.queue.put((0, sub))    # Retry
            except Exception as e:
                import traceback
                traceback.print_exc()
                with open('errors.log', 'a') as errFile:
                    errFile.write('[%s] %s\n' % (type(e), str(e)))

    def run(self):
        threads = [gevent.spawn(self.scan, i) for i in range(self.options.threads)]
        gevent.joinall(threads)


def run_process(*params):
    signal.signal(signal.SIGINT, user_abort)
    s = SubNameBrute(*params)
    s.run()


def wildcard_test(domain, level=1):
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = dns_servers
        answers = r.query('lijiejie-not-existed-test.%s' % domain)
        ips = ', '.join(sorted([answer.address for answer in answers]))
        if level == 1:
            print 'any-sub.%s\t%s' % (domain.ljust(30), ips)
            wildcard_test('any-sub.%s' % domain, 2)
        elif level == 2:
            exit(0)
    except Exception as e:
        return domain


# check file existence
def get_sub_file_path():
    if options.full_scan and options.file == 'subnames.txt':
        path = 'dict/subnames_full.txt'
    else:
        if os.path.exists(options.file):
            path = options.file
        elif os.path.exists('dict/%s' % options.file):
            path = 'dict/%s' % options.file
        else:
            print_msg('[ERROR] Names file not found: %s' % options.file)
            exit(-1)
    return path


if __name__ == '__main__':
    options, args = parse_args()
    print '''  SubDomainsBrute v1.2
  https://github.com/lijiejie/subDomainsBrute
'''
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
        print '[+] Run wildcard test'
        domain = wildcard_test(args[0])
        options.file = get_sub_file_path()
        print '[+] Start %s scan process' % options.process
        print '[+] Please wait while scanning ... \n'
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
        print '[ERROR] User aborted the scan!'
        for p in all_process:
            p.terminate()
    except Exception as e:
        print '[ERROR] %s' % str(e)

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
    print 'Output file is %s' % out_file_name
