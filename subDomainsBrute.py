#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
    subDomainsBrute 1.0.3
    A simple and fast sub domains brute tool for pentesters
    my[at]lijiejie.com (http://www.lijiejie.com)
'''


import Queue
import sys
import dns.resolver
import threading
import time
import optparse
import random
from lib.consle_width import getTerminalSize


class SubNameBrute:
    def __init__(self, target, options):
        self.target = target.strip()
        self.options = options
        self.ignore_intranet = options.i
        self.thread_count = 0
        self.scan_count = self.found_count = 0
        self.lock = threading.Lock()
        self.console_width = getTerminalSize()[0] - 2
        self.msg_queue = Queue.Queue()
        self.STOP_ME = False
        threading.Thread(target=self._print_msg).start()    # print thread
        self._load_dns_servers()
        self.resolvers = [dns.resolver.Resolver() for _ in range(self.dns_count)]
        for _ in self.resolvers:
            _.lifetime = _.timeout = 5.0
        self._load_sub_names()
        self._load_next_sub()
        if options.output:
            outfile = options.output
        else:
            outfile = target + '.txt' if not options.full_scan else target + '_full.txt'
        self.outfile = open(outfile, 'w')
        self.ip_dict = {}
        self.sub_timeout_count = {}


    def _load_dns_servers(self):
        print '[+] Initializing, validate DNS servers ...'
        self.dns_servers = dns.resolver.Resolver().nameservers * 2
        with open('dict/dns_servers.txt') as f:
            for line in f:
                server = line.strip()
                while True:
                    if threading.activeCount() < 200:
                        t = threading.Thread(target=self._test_server, args=(server,))
                        t.start()
                        break
                    else:
                        time.sleep(0.1)

        while threading.activeCount() > 2:
            time.sleep(0.1)
        self.dns_count = len(self.dns_servers)
        sys.stdout.write('\n')
        print '[+] Found %s available DNS servers in total' % self.dns_count


    def _test_server(self, server):
        resolver = dns.resolver.Resolver()
        resolver.lifetime = resolver.timeout = 2.0
        try:
            resolver.nameservers = [server]
            answers = resolver.query('google-public-dns-a.google.com')    # test look up google public dns
            if answers[0].address != '8.8.8.8':
                raise Exception('incorrect DNS response')
            if server not in self.dns_servers:
                self.dns_servers.append(server)
                self.msg_queue.put('[+] Check DNS Server %s < OK >   Found %s' % (server.ljust(16), len(self.dns_servers)) )
        except:
            self.msg_queue.put('[+] Check DNS Server %s <Fail>   Found %s' % (server.ljust(16), len(self.dns_servers)) )


    def _load_sub_names(self):
        self.msg_queue.put ('[+] Load sub names ...')
        self.queue = Queue.Queue()
        if self.options.full_scan:
            _file = 'dict/subnames_full.txt'
        else:
            _file = 'dict/subnames.txt'
        sub_names = set()
        lst_subs = []
        GROUP_SIZE = 10 if not self.options.full_scan else 30
        with open(_file) as f:
            for line in f:
                sub = line.strip()
                if sub and sub not in sub_names:
                    sub_names.add(sub)
                    tmp_set = {sub}
                    while len(tmp_set) > 0:
                        item = tmp_set.pop()
                        if item.find('{alphnum}') >= 0:
                            for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                                tmp_set.add(item.replace('{alphnum}', _letter, 1) )
                        elif item.find('{alpha}') >= 0:
                            for _letter in 'abcdefghijklmnopqrstuvwxyz':
                                tmp_set.add(item.replace('{alpha}', _letter, 1) )
                        elif item.find('{num}') >= 0:
                            for _letter in '0123456789':
                                tmp_set.add(item.replace('{num}', _letter, 1) )
                        else:
                            lst_subs.append(item)
                            if len(lst_subs) >= GROUP_SIZE:
                                self.queue.put(lst_subs)
                                lst_subs = []
                            sub_names.add(item)
        if lst_subs:
            self.queue.put(lst_subs)


    def _load_next_sub(self):
        self.msg_queue.put( '[+] Load next level subs ...')
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
                                tmp_set.add(item.replace('{alphnum}', _letter, 1) )
                        elif item.find('{alpha}') >= 0:
                            for _letter in 'abcdefghijklmnopqrstuvwxyz':
                                tmp_set.add(item.replace('{alpha}', _letter, 1) )
                        elif item.find('{num}') >= 0:
                            for _letter in '0123456789':
                                tmp_set.add(item.replace('{num}', _letter, 1) )
                        else:
                            next_subs.append(item)
        self.next_subs = next_subs


    def _update_scan_count(self):
        self.last_scanned = time.time()
        self.scan_count += 1

    def _update_found_count(self):
        self.found_count += 1


    def _print_msg(self):
        while not self.STOP_ME:
            try:
                _msg = self.msg_queue.get(timeout=0.1)
            except:
                continue

            if _msg == 'status':
                msg = '%s Found| %s groups| %s scanned in %.1f seconds| %s threads' % (
                    self.found_count, self.queue.qsize(), self.scan_count, time.time() - self.start_time, self.thread_count)
                sys.stdout.write('\r' + ' ' * (self.console_width -len(msg)) + msg)
            elif _msg.startswith('[+] Check DNS Server'):
                sys.stdout.write('\r' + _msg + ' ' * (self.console_width -len(_msg)))
            else:
                sys.stdout.write('\r' + _msg + ' ' * (self.console_width -len(_msg)) +'\n')
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
        thread_id = int( threading.currentThread().getName() )
        start = random.randint(0, self.dns_count - 1)
        if start > self.dns_count - 3:
            start = self.dns_count - 3
        self.resolvers[thread_id].nameservers = self.dns_servers[start: start+2]

        _lst_subs =[]
        self.lock.acquire()
        self.thread_count += 1
        self.lock.release()

        while not self.STOP_ME:
            if not _lst_subs:
                try:
                    _lst_subs = self.queue.get(timeout=0.1)
                except:
                    if time.time() - self.last_scanned > 1.1:
                        break
                    else:
                        continue
            sub = _lst_subs.pop()
            _sub = sub.split('.')[-1]
            while not self.STOP_ME:
                try:
                    cur_sub_domain = sub + '.' + self.target
                    self._update_scan_count()
                    self.msg_queue.put('status')
                    answers = self.resolvers[thread_id].query(cur_sub_domain)
                    is_wildcard_record = False
                    if answers:
                        ips = ', '.join( sorted([answer.address for answer in answers]) )
                        if ips in ['1.1.1.1', '127.0.0.1', '0.0.0.0']:
                            break

                        if ips not in self.ip_dict:
                            self.ip_dict[ips] = 1
                        else:
                            self.ip_dict[ips] += 1
                            if self.ip_dict[ips] > 6:    # a wildcard DNS record
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
                                d.resolvers[thread_id].query('lijiejietest.' + cur_sub_domain)
                            except dns.resolver.NXDOMAIN, e:
                                _lst = []
                                if_put_one = (self.queue.qsize() < self.dns_count * 2)
                                for i in self.next_subs:
                                    _lst.append(i + '.' + sub)
                                    if if_put_one:
                                        self.put(_lst)
                                    elif len(_lst) >= 10:
                                        self.queue.put(_lst)
                                        _lst = []
                                if _lst:
                                    self.queue.put(_lst)
                            except Exception, e:
                                pass
                        break
                except (dns.resolver.NXDOMAIN, dns.name.EmptyLabel) as e:
                    break
                except dns.resolver.NoNameservers, e:
                    self.queue.put([sub])
                    break
                except dns.resolver.NoAnswer, e:
                    self.queue.put([sub])
                    break
                except dns.exception.Timeout as e:
                    if _sub not in self.sub_timeout_count:
                        self.sub_timeout_count[_sub] = 1
                    else:
                        self.sub_timeout_count[_sub] += 1
                    if self.sub_timeout_count[_sub] >= 6:    # give up
                        break
                    elif self.sub_timeout_count[_sub] >= 4:
                        self.queue.put([sub])    # enqueue ,let another thread test it
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
        for i in range(self.dns_count):
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

        while self.thread_count > 0:
            time.sleep(0.2)
        self.STOP_ME = True

if __name__ == '__main__':
    parser = optparse.OptionParser('usage: %prog [options] target.com', version="%prog 1.0.3")
    parser.add_option('--full', dest='full_scan', default=False, action='store_true',
              help='Full scan, a large NAMES FILE will be used during the scan')
    parser.add_option('-i', '--ignore-intranet', dest='i', default=False, action='store_true',
              help='Ignore domains pointed to private IPs')
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
