#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
    subDomainsBrute 1.0.4
    A simple and fast sub domains brute tool for pentesters
    my[at]lijiejie.com (http://www.lijiejie.com)
"""

import Queue
import sys
import dns.resolver
import threading
import time
import optparse
import re
import os
from lib.consle_width import getTerminalSize


class SubNameBrute:
    def __init__(self, target, options):
        self.target = target.strip()
        self.options = options
        self.ignore_intranet = options.i
        self.thread_count = self.scan_count = self.found_count = 0
        self.lock = threading.Lock()
        self.console_width = getTerminalSize()[0] - 2
        self.msg_queue = Queue.Queue()
        self.STOP_ME = False
        threading.Thread(target=self._print_msg).start()
        self._load_dns_servers()
        self.resolvers = [dns.resolver.Resolver() for _ in range(options.threads)]
        for _ in self.resolvers:
            _.lifetime = _.timeout = 6.0
        self._load_next_sub()
        self.queue = Queue.Queue()
        t = threading.Thread(target=self._load_sub_names)
        t.start()
        while not self.queue.qsize() > 0 and t.isAlive():
            time.sleep(0.1)
        if options.output:
            outfile = options.output
        else:
            outfile = target + '.txt' if not options.full_scan else target + '_full.txt'
        self.outfile = open(outfile, 'w')
        self.ip_dict = {}
        self.last_scanned = time.time()
        self.ex_resolver = dns.resolver.Resolver()
        self.start_time = None

    def _load_dns_servers(self):
        print '[+] Initializing, validate DNS servers ...'
        self.dns_servers = []
        with open('dict/dns_servers.txt') as f:
            for line in f:
                server = line.strip()
                if not server:
                    continue
                while True:
                    if threading.activeCount() < 50:
                        t = threading.Thread(target=self._test_server, args=(server,))
                        t.start()
                        break
                    else:
                        time.sleep(0.1)

        while threading.activeCount() > 2:
            time.sleep(0.1)
        self.dns_count = len(self.dns_servers)
        sys.stdout.write('\n')
        print '[+] Found %s available DNS Servers in total' % self.dns_count
        if self.dns_count == 0:
            print '[ERROR] No DNS Servers available.'
            self.STOP_ME = True
            sys.exit(-1)

    def _test_server(self, server):
        resolver = dns.resolver.Resolver()
        resolver.lifetime = resolver.timeout = 20.0
        try:
            resolver.nameservers = [server]
            answers = resolver.query('public-dns-a.baidu.com')    # test lookup a existed domain
            if answers[0].address != '180.76.76.76':
                raise Exception('incorrect DNS response')
            try:
                resolver.query('test.bad.dns.lijiejie.com')    # Non-existed domain test
                with open('bad_dns_servers.txt', 'a') as f:
                    f.write(server + '\n')
                self.msg_queue.put('[+] Bad DNS Server found %s' % server)
            except:
                self.dns_servers.append(server)
            self.msg_queue.put('[+] Check DNS Server %s < OK >   Found %s' % (server.ljust(16), len(self.dns_servers)))
        except:
            self.msg_queue.put('[+] Check DNS Server %s <Fail>   Found %s' % (server.ljust(16), len(self.dns_servers)))

    def _load_sub_names(self):
        self.msg_queue.put('[+] Load sub names ...')
        if self.options.full_scan and self.options.file == 'subnames.txt':
            _file = 'dict/subnames_full.txt'
        else:
            if os.path.exists(self.options.file):
                _file = self.options.file
            elif os.path.exists('dict/%s' % self.options.file):
                _file = 'dict/%s' % self.options.file
            else:
                self.msg_queue.put('[ERROR] Names file not exists: %s' % self.options.file)
                return

        normal_lines = []
        wildcard_lines = []
        wildcard_list = []
        regex_list = []
        lines = set()
        with open(_file) as f:
            for line in f.xreadlines():
                sub = line.strip()
                if not sub or sub in lines:
                    continue
                lines.add(sub)

                if sub.find('{alphnum}') >= 0 or sub.find('{alpha}') >= 0 or sub.find('{num}') >= 0:
                    wildcard_lines.append(sub)
                    sub = sub.replace('{alphnum}', '[a-z0-9]')
                    sub = sub.replace('{alpha}', '[a-z]')
                    sub = sub.replace('{num}', '[0-9]')
                    if sub not in wildcard_list:
                        wildcard_list.append(sub)
                        regex_list.append('^' + sub + '$')
                else:
                    normal_lines.append(sub)
        pattern = '|'.join(regex_list)
        if pattern:
            _regex = re.compile(pattern)
            if _regex:
                for line in normal_lines:
                    if _regex.search(line):
                        normal_lines.remove(line)

        lst_subs = []
        GROUP_SIZE = 1 if not self.options.full_scan else 1    # disable scan by groups

        for item in normal_lines:
            lst_subs.append(item)
            if len(lst_subs) >= GROUP_SIZE:
                self.queue.put(lst_subs)
                lst_subs = []

        sub_queue = Queue.LifoQueue()
        for line in wildcard_lines:
            sub_queue.put(line)
            while sub_queue.qsize() > 0:
                item = sub_queue.get()
                if item.find('{alphnum}') >= 0:
                    for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                        sub_queue.put(item.replace('{alphnum}', _letter, 1))
                elif item.find('{alpha}') >= 0:
                    for _letter in 'abcdefghijklmnopqrstuvwxyz':
                        sub_queue.put(item.replace('{alpha}', _letter, 1))
                elif item.find('{num}') >= 0:
                    for _letter in '0123456789':
                        sub_queue.put(item.replace('{num}', _letter, 1))
                else:
                    lst_subs.append(item)
                    if len(lst_subs) >= GROUP_SIZE:
                        while self.queue.qsize() > 10000:
                            time.sleep(0.1)
                        self.queue.put(lst_subs)
                        lst_subs = []

        if lst_subs:
            self.queue.put(lst_subs)

    def _load_next_sub(self):
        self.msg_queue.put('[+] Load next level subs ...')
        next_subs = []
        _file = 'dict/next_sub.txt' if not self.options.full_scan else 'dict/next_sub_full.txt'
        with open(_file) as f:
            for line in f:
                sub = line.strip()
                if sub and sub not in next_subs:
                    tmp_set = {sub}
                    while len(tmp_set) > 0:
                        item = tmp_set.pop()
                        if item.find('{alphnum}') >= 0:
                            for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                                tmp_set.add(item.replace('{alphnum}', _letter, 1))
                        elif item.find('{alpha}') >= 0:
                            for _letter in 'abcdefghijklmnopqrstuvwxyz':
                                tmp_set.add(item.replace('{alpha}', _letter, 1))
                        elif item.find('{num}') >= 0:
                            for _letter in '0123456789':
                                tmp_set.add(item.replace('{num}', _letter, 1))
                        elif item not in next_subs:
                            next_subs.append(item)
        self.next_subs = next_subs

    def _update_scan_count(self):
        self.last_scanned = time.time()
        self.scan_count += 1

    def _update_found_count(self):
        # no need to use a lock
        self.found_count += 1

    def _print_msg(self):
        while not self.STOP_ME:
            try:
                _msg = self.msg_queue.get(timeout=0.1)
            except:
                continue

            if _msg == 'status':
                msg = '%s Found| %s groups| %s scanned in %.1f seconds| %s threads' % (
                    self.found_count, self.queue.qsize(), self.scan_count, time.time() - self.start_time,
                    self.thread_count)
                sys.stdout.write('\r' + ' ' * (self.console_width - len(msg)) + msg)
            elif _msg.startswith('[+] Check DNS Server'):
                sys.stdout.write('\r' + _msg + ' ' * (self.console_width - len(_msg)))
            else:
                sys.stdout.write('\r' + _msg + ' ' * (self.console_width - len(_msg)) + '\n')
            sys.stdout.flush()

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
        thread_id = int(threading.currentThread().getName())
        self.resolvers[thread_id].nameservers = [self.dns_servers[thread_id % self.dns_count]]

        _lst_subs = []
        self.lock.acquire()
        self.thread_count += 1
        self.lock.release()

        while not self.STOP_ME:
            if not _lst_subs:
                try:
                    _lst_subs = self.queue.get(timeout=0.1)
                except:
                    if time.time() - self.last_scanned > 2.0:
                        break
                    else:
                        continue
            sub = _lst_subs.pop()
            _sub = sub.split('.')[-1]
            _sub_timeout_count = 0
            while not self.STOP_ME:
                try:
                    cur_sub_domain = sub + '.' + self.target
                    self._update_scan_count()
                    self.msg_queue.put('status')
                    try:
                        answers = self.resolvers[thread_id].query(cur_sub_domain)
                    except dns.resolver.NoAnswer, e:
                        answers = self.ex_resolver.query(cur_sub_domain)
                    is_wildcard_record = False
                    if answers:
                        ips = ', '.join(sorted([answer.address for answer in answers]))
                        if ips in ['1.1.1.1', '127.0.0.1', '0.0.0.0']:
                            break

                        if (_sub, ips) not in self.ip_dict:
                            self.ip_dict[(_sub, ips)] = 1
                        else:
                            self.ip_dict[(_sub, ips)] += 1

                        if ips not in self.ip_dict:
                            self.ip_dict[ips] = 1
                        else:
                            self.ip_dict[ips] += 1

                        if self.ip_dict[(_sub, ips)] > 3 or self.ip_dict[ips] > 6:
                            is_wildcard_record = True

                        if is_wildcard_record:
                            break

                        if (not self.ignore_intranet) or (not SubNameBrute.is_intranet(answers[0].address)):
                            self._update_found_count()
                            msg = cur_sub_domain.ljust(30) + ips
                            self.msg_queue.put(msg)
                            self.msg_queue.put('status')
                            self.outfile.write(cur_sub_domain.ljust(30) + '\t' + ips + '\n')
                            self.outfile.flush()

                            try:
                                self.resolvers[thread_id].query('lijiejietest.' + cur_sub_domain)
                            except dns.resolver.NXDOMAIN, e:
                                _lst = []
                                if_put_one = (self.queue.qsize() < self.dns_count * 5)
                                for i in self.next_subs:
                                    _lst.append(i + '.' + sub)
                                    if if_put_one:
                                        self.queue.put(_lst)
                                        _lst = []
                                    elif len(_lst) >= 10:
                                        self.queue.put(_lst)
                                        _lst = []
                                if _lst:
                                    self.queue.put(_lst)
                            except:
                                pass
                        break
                except (dns.resolver.NXDOMAIN, dns.name.EmptyLabel) as e:
                    break
                except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
                    _sub_timeout_count += 1
                    if _sub_timeout_count >= 6:  # give up
                        break
                except Exception, e:
                    with open('errors.log', 'a') as errFile:
                        errFile.write('%s [%s] %s %s\n' % (threading.current_thread, type(e), cur_sub_domain, e))
                    break
        self.lock.acquire()
        self.thread_count -= 1
        self.lock.release()
        self.msg_queue.put('status')

    def run(self):
        self.start_time = time.time()
        for i in range(self.options.threads):
            try:
                t = threading.Thread(target=self._scan, name=str(i))
                t.setDaemon(True)
                t.start()
            except:
                pass
        while self.thread_count > 0:
            try:
                time.sleep(1.0)
            except KeyboardInterrupt, e:
                msg = '[WARNING] User aborted, wait all slave threads to exit...'
                sys.stdout.write('\r' + msg + ' ' * (self.console_width - len(msg)) + '\n\r')
                sys.stdout.flush()
                self.STOP_ME = True
        self.STOP_ME = True


if __name__ == '__main__':
    parser = optparse.OptionParser('usage: %prog [options] target.com', version="%prog 1.0.4")
    parser.add_option('-f', dest='file', default='subnames.txt',
                      help='A file contains new line delimited subs, default is subnames.txt.')
    parser.add_option('--full', dest='full_scan', default=False, action='store_true',
                      help='Full scan, NAMES FILE subnames_full.txt will be used to brute')
    parser.add_option('-i', '--ignore-intranet', dest='i', default=False, action='store_true',
                      help='Ignore domains pointed to private IPs')
    parser.add_option('-t', '--threads', dest='threads', default=200, type=int,
                      help='Num of scan threads, 200 by default')
    parser.add_option('-o', '--output', dest='output', default=None,
                      type='string', help='Output file name. default is {target}.txt')

    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        sys.exit(0)

    d = SubNameBrute(target=args[0], options=options)
    d.run()
    d.outfile.flush()
    d.outfile.close()
