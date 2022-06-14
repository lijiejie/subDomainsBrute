import re
import time
import dns.resolver
import gevent
from gevent import monkey
monkey.patch_all()
import random
from gevent.queue import PriorityQueue
from gevent.lock import RLock
from .common import is_intranet
from requests.packages.urllib3.contrib import pyopenssl as reqs


class SubNameBrute(object):
    def __init__(self, *params):
        self.domain, self.options, self.process_num, self.dns_servers, self.next_subs, \
            self.scan_count, self.found_count, self.queue_size_array, tmp_dir = params
        self.dns_count = len(self.dns_servers)
        self.scan_count_local = 0
        self.found_count_local = 0
        self.resolvers = [dns.resolver.Resolver(configure=False) for _ in range(self.options.threads)]
        for r in self.resolvers:
            r.lifetime = 6.0
            r.timeout = 10.0
        self.queue = PriorityQueue()
        self.priority = 0
        self.ip_dict = {}
        self.found_subs = set()
        self.cert_subs = set()
        self.timeout_subs = {}
        self.no_server_subs = {}
        self.count_time = time.time()
        self.outfile = open('%s/%s_part_%s.txt' % (tmp_dir, self.domain, self.process_num), 'w')
        self.normal_names_set = set()
        self.load_sub_names()
        self.lock = RLock()
        self.threads_status = ['1'] * self.options.threads

    def load_sub_names(self):
        normal_lines = []
        wildcard_lines = []
        wildcard_set = set()
        regex_list = []
        lines = set()
        with open(self.options.file) as inFile:
            for line in inFile.readlines():
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

    def update_counter(self):
        while True:
            if '1' not in self.threads_status:
                return
            self.scan_count.value += self.scan_count_local
            self.scan_count_local = 0
            self.queue_size_array[self.process_num] = self.queue.qsize()
            if self.found_count_local:
                self.found_count.value += self.found_count_local
                self.found_count_local = 0
            self.count_time = time.time()
            gevent.sleep(0.5)

    def check_https_alt_names(self, domain):
        try:
            x509 = reqs.OpenSSL.crypto.load_certificate(
                reqs.OpenSSL.crypto.FILETYPE_PEM,
                reqs.ssl.get_server_certificate((domain, 443))
            )
            for item in reqs.get_subj_alt_name(x509):
                if item[0].upper() == 'DNS':
                    name = item[1].lower()
                    if name.endswith(self.domain):
                        sub = name[:len(name) - len(self.domain) - 1]    # new sub
                        sub = sub.replace('*', '')
                        sub = sub.strip('.')
                        if sub and sub not in self.found_subs and \
                                sub not in self.normal_names_set and sub not in self.cert_subs:
                            self.cert_subs.add(sub)
                            self.queue.put((0, sub))
        except Exception as e:
            pass

    def scan(self, j):
        self.resolvers[j].nameservers = [self.dns_servers[j % self.dns_count]]
        if self.dns_count > 1:
            while True:
                s = random.choice(self.dns_servers)
                if s != self.dns_servers[j % self.dns_count]:
                    self.resolvers[j].nameservers.append(s)
                    break
        empty_counter = 0
        while True:
            try:

                brace_count, sub = self.queue.get_nowait()
                self.threads_status[j] = '1'
                empty_counter = 0
            except gevent.queue.Empty as e:
                empty_counter += 1
                if empty_counter > 10:
                    self.threads_status[j] = '0'
                if '1' not in self.threads_status:
                    break
                else:
                    gevent.sleep(0.1)
                    continue
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

            try:
                if sub in self.found_subs:
                    continue

                self.scan_count_local += 1
                cur_domain = sub + '.' + self.domain
                answers = self.resolvers[j].query(cur_domain)

                if answers:
                    self.found_subs.add(sub)
                    ips = ', '.join(sorted([answer.address for answer in answers]))
                    invalid_ip_found = False
                    for answer in answers:
                        if answer.address in ['1.1.1.1', '127.0.0.1', '0.0.0.0', '0.0.0.1']:
                            invalid_ip_found = True
                    if invalid_ip_found:
                        continue
                    if self.options.i and is_intranet(answers[0].address):
                        continue

                    try:
                        cname = str(answers.canonical_name)[:-1]
                        if cname != cur_domain and cname.endswith(self.domain):
                            cname_sub = cname[:len(cname) - len(self.domain) - 1]    # new sub
                            if cname_sub not in self.found_subs and cname_sub not in self.normal_names_set:
                                self.queue.put((0, cname_sub))
                    except Exception as e:
                        print(e)
                        pass

                    try:
                        self.scan_count_local += 1
                        answers = self.resolvers[j].query(cur_domain, 'cname')
                        cname = answers[0].target.to_unicode().rstrip('.')
                        if cname.endswith(self.domain) and cname not in self.found_subs:
                            cname_sub = cname[:len(cname) - len(self.domain) - 1]    # new sub
                            if cname_sub not in self.normal_names_set:
                                # self.found_subs.add(cname)
                                self.queue.put((0, cname_sub))
                    except Exception as e:
                        pass

                    first_level_sub = sub.split('.')[-1]
                    max_found = 20

                    if self.options.w:
                        first_level_sub = ''
                        max_found = 3

                    if (first_level_sub, ips) not in self.ip_dict:
                        self.ip_dict[(first_level_sub, ips)] = 1
                    else:
                        self.ip_dict[(first_level_sub, ips)] += 1
                        if self.ip_dict[(first_level_sub, ips)] > max_found:
                            continue

                    self.found_count_local += 1

                    self.outfile.write(cur_domain.ljust(30) + '\t' + ips + '\n')
                    self.outfile.flush()
                    if not self.options.no_cert_check:
                        with gevent.Timeout(10, False):
                            self.check_https_alt_names(cur_domain)
                    try:
                        self.scan_count_local += 1
                        self.resolvers[j].query('lijiejie-test-not-existed.' + cur_domain)
                    except (dns.resolver.NXDOMAIN, ) as e:    # dns.resolver.NoAnswer
                        if self.queue.qsize() < 20000:
                            for _ in self.next_subs:
                                self.queue.put((0, _ + '.' + sub))
                        else:
                            self.queue.put((1, '{next_sub}.' + sub))
                    except Exception as e:
                        pass

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                pass
            except dns.resolver.NoNameservers as e:
                self.no_server_subs[sub] = self.no_server_subs.get(sub, 0) + 1
                if self.no_server_subs[sub] <= 3:
                    self.queue.put((0, sub))    # Retry
            except dns.exception.Timeout as e:
                self.timeout_subs[sub] = self.timeout_subs.get(sub, 0) + 1
                if self.timeout_subs[sub] <= 1:
                    self.queue.put((0, sub))    # Retry
            except Exception as e:
                import traceback
                traceback.print_exc()
                with open('errors.log', 'a') as errFile:
                    errFile.write('[%s] %s\n' % (type(e), str(e)))

    def run(self):
        threads = [gevent.spawn(self.scan, i) for i in range(self.options.threads)]
        threads.insert(0, gevent.spawn(self.update_counter))
        gevent.joinall(threads)
