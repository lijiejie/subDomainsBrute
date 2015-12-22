#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# A simple and fast sub domains brute tool for pentesters
# my[at]lijiejie.com (http://www.lijiejie.com)

import Queue
import sys
import dns.resolver
import threading
import time
import optparse
import os
from lib.consle_width import getTerminalSize


class DNSBrute:
    def __init__(self, target, names_file, ignore_intranet, threads_num, output):
        self.target = target.strip()
        self.names_file = names_file
        self.ignore_intranet = ignore_intranet
        self.thread_count = self.threads_num = threads_num
        self.scan_count = self.found_count = 0
        self.lock = threading.Lock()
        self.console_width = getTerminalSize()[0] - 2    # Cal terminal width when starts up
        self.resolvers = [dns.resolver.Resolver() for _ in range(threads_num)]
        self._load_dns_servers()
        self._load_sub_names()
        self._load_next_sub()
        outfile = target + '.txt' if not output else output
        self.outfile = open(outfile, 'w')   # won't close manually
        self.ip_dict = {}
        self.STOP_ME = False

    def _load_dns_servers(self):
        dns_servers = []
        with open('dict/dns_servers.txt') as f:
            for line in f:
                server = line.strip()
                if server.count('.') == 3 and server not in dns_servers:
                    dns_servers.append(server)
        self.dns_servers = dns_servers
        self.dns_count = len(dns_servers)

    def _load_sub_names(self):
        self.queue = Queue.Queue()
        file = 'dict/' + self.names_file if not os.path.exists(self.names_file) else self.names_file
        with open(file) as f:
            for line in f:
                sub = line.strip()
                if sub: self.queue.put(sub)

    def _load_next_sub(self):
        next_subs = []
        with open('dict/next_sub.txt') as f:
            for line in f:
                sub = line.strip()
                if sub and sub not in next_subs:
                    next_subs.append(sub)
        self.next_subs = next_subs

    def _update_scan_count(self):
        self.lock.acquire()
        self.scan_count += 1
        self.lock.release()

    def _print_progress(self):
        self.lock.acquire()
        msg = '%s found | %s remaining | %s scanned in %.2f seconds' % (
            self.found_count, self.queue.qsize(), self.scan_count, time.time() - self.start_time)
        sys.stdout.write('\r' + ' ' * (self.console_width -len(msg)) + msg)
        sys.stdout.flush()
        self.lock.release()

    @staticmethod
    def is_intranet(ip):
        ret = ip.split('.')
        if not len(ret) == 4:
            return True
        if ret[0] == '10':
            return True
        if ret[0] == '172' and 16 <= int(ret[1]) <= 32:
            return True
        if ret[0] == '192' and ret[1] == '168':
            return True
        return False

    def _scan(self):
        thread_id = int( threading.currentThread().getName() )
        self.resolvers[thread_id].nameservers.insert(0, self.dns_servers[thread_id % self.dns_count])
        self.resolvers[thread_id].lifetime = self.resolvers[thread_id].timeout = 10.0
        while self.queue.qsize() > 0 and not self.STOP_ME and self.found_count < 4000:    # limit found count to 4000
            sub = self.queue.get(timeout=1.0)
            for _ in range(6):
                try:
                    cur_sub_domain = sub + '.' + self.target
                    answers = d.resolvers[thread_id].query(cur_sub_domain)
                    is_wildcard_record = False
                    if answers:
                        for answer in answers:
                            self.lock.acquire()
                            if answer.address not in self.ip_dict:
                                self.ip_dict[answer.address] = 1
                            else:
                                self.ip_dict[answer.address] += 1
                                if self.ip_dict[answer.address] > 2:    # a wildcard DNS record
                                    is_wildcard_record = True
                            self.lock.release()
                        if is_wildcard_record:
                            self._update_scan_count()
                            self._print_progress()
                            continue
                        ips = ', '.join([answer.address for answer in answers])
                        if (not self.ignore_intranet) or (not DNSBrute.is_intranet(answers[0].address)):
                            self.lock.acquire()
                            self.found_count += 1
                            msg = cur_sub_domain.ljust(30) + ips
                            sys.stdout.write('\r' + msg + ' ' * (self.console_width- len(msg)) + '\n\r')
                            sys.stdout.flush()
                            self.outfile.write(cur_sub_domain.ljust(30) + '\t' + ips + '\n')
                            self.lock.release()
                            for i in self.next_subs:
                                self.queue.put(i + '.' + sub)
                        break
                except dns.resolver.NoNameservers, e:
                    break
                except Exception, e:
                    pass
            self._update_scan_count()
            self._print_progress()
        self._print_progress()
        self.lock.acquire()
        self.thread_count -= 1
        self.lock.release()

    def run(self):
        self.start_time = time.time()
        for i in range(self.threads_num):
            t = threading.Thread(target=self._scan, name=str(i))
            t.setDaemon(True)
            t.start()
        while self.thread_count > 1:
            try:
                time.sleep(1.0)
            except KeyboardInterrupt,e:
                msg = '[WARNING] User aborted, wait all slave threads to exit...'
                sys.stdout.write('\r' + msg + ' ' * (self.console_width- len(msg)) + '\n\r')
                sys.stdout.flush()
                self.STOP_ME = True

if __name__ == '__main__':
    parser = optparse.OptionParser('usage: %prog [options] target.com')
    parser.add_option('-t', '--threads', dest='threads_num',
              default=60, type='int',
              help='Number of threads. default = 30')
    parser.add_option('-f', '--file', dest='names_file', default='dict/subnames.txt',
              type='string', help='Dict file used to brute sub names')
    parser.add_option('-i', '--ignore-intranet', dest='i', default=False, action='store_true',
              help='Ignore domains pointed to private IPs.')
    parser.add_option('-o', '--output', dest='output', default=None,
              type='string', help='Output file name. default is {target}.txt')

    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        sys.exit(0)

    d = DNSBrute(target=args[0], names_file=options.names_file,
                 ignore_intranet=options.i,
                 threads_num=options.threads_num,
                 output=options.output)
    d.run()
