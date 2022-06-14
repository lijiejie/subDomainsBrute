# -*- encoding: utf-8 -*-

import re
import time
import asyncio
import random
import socket
import platform
import sys
import os
import dns.asyncresolver
from asyncio import PriorityQueue
from .common import is_intranet
from async_timeout import timeout


if platform.system() == 'Windows':
    try:
        def _call_connection_lost(self, exc):
            try:
                self._protocol.connection_lost(exc)
            finally:
                if hasattr(self._sock, 'shutdown'):
                    try:
                        if self._sock.fileno() != -1:
                            self._sock.shutdown(socket.SHUT_RDWR)
                    except Exception as e:
                        pass
                self._sock.close()
                self._sock = None
                server = self._server
                if server is not None:
                    server._detach()
                    self._server = None

        asyncio.proactor_events._ProactorBasePipeTransport._call_connection_lost = _call_connection_lost
    except Exception as e:
        pass

if sys.version_info.major == 3 and sys.version_info.minor == 6:
    # I'll do this first, mute stderr
    # Since python3.6 throws exception from inner function that can not be captured by except ...
    sys.stderr = open(os.devnull, 'w')


class SubNameBrute(object):
    def __init__(self, *params):
        self.domain, self.options, self.process_num, self.dns_servers, self.next_subs, \
            self.scan_count, self.found_count, self.queue_size_array, tmp_dir = params
        self.dns_count = len(self.dns_servers)
        self.scan_count_local = 0
        self.found_count_local = 0
        self.resolvers = [dns.asyncresolver.Resolver(configure=False) for _ in range(self.options.threads)]
        for r in self.resolvers:
            r.lifetime = 6.0
            r.timeout = 10.0
        self.queue = PriorityQueue()
        self.ip_dict = {}
        self.found_subs = set()
        self.cert_subs = set()
        self.timeout_subs = {}
        self.no_server_subs = {}
        self.count_time = time.time()
        self.outfile = open('%s/%s_part_%s.txt' % (tmp_dir, self.domain, self.process_num), 'w')
        self.normal_names_set = set()
        self.lock = asyncio.Lock()
        self.threads_status = ['1'] * self.options.threads

    async def load_sub_names(self):
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
            await self.queue.put((0, _))    # priority set to 0
        for _ in wildcard_lines[self.process_num::self.options.process]:
            await self.queue.put(_)

    async def update_counter(self):
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
            await asyncio.sleep(0.5)

    async def check_https_alt_names(self, domain):
        try:
            reader, _ = await asyncio.open_connection(
                host=domain,
                port=443,
                ssl=True,
                server_hostname=domain,
            )
            for item in reader._transport.get_extra_info('peercert')['subjectAltName']:
                if item[0].upper() == 'DNS':
                    name = item[1].lower()
                    if name.endswith(self.domain):
                        sub = name[:len(name) - len(self.domain) - 1]    # new sub
                        sub = sub.replace('*', '')
                        sub = sub.strip('.')
                        if sub and sub not in self.found_subs and \
                                sub not in self.normal_names_set and sub not in self.cert_subs:
                            self.cert_subs.add(sub)
                            await self.queue.put((0, sub))
        except Exception as e:
            pass


    async def do_query(self, j, cur_domain):
        async with timeout(10.2):
            return await self.resolvers[j].resolve(cur_domain, 'A')
        # asyncio.wait_for did not work properly
        # hang up in some cases, we use async_timeout instead
        # return await asyncio.wait_for(self.resolvers[j].resolve(cur_domain, 'A', lifetime=8), timeout=9)

    async def scan(self, j):
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
            except asyncio.queues.QueueEmpty as e:
                empty_counter += 1
                if empty_counter > 10:
                    self.threads_status[j] = '0'
                if '1' not in self.threads_status:
                    break
                else:
                    await asyncio.sleep(0.1)
                    continue

            if brace_count > 0:
                brace_count -= 1
                if sub.find('{next_sub}') >= 0:
                    for _ in self.next_subs:
                        await self.queue.put((0, sub.replace('{next_sub}', _)))
                if sub.find('{alphnum}') >= 0:
                    for _ in 'abcdefghijklmnopqrstuvwxyz0123456789':
                        await self.queue.put((brace_count, sub.replace('{alphnum}', _, 1)))
                elif sub.find('{alpha}') >= 0:
                    for _ in 'abcdefghijklmnopqrstuvwxyz':
                        await self.queue.put((brace_count, sub.replace('{alpha}', _, 1)))
                elif sub.find('{num}') >= 0:
                    for _ in '0123456789':
                        await self.queue.put((brace_count, sub.replace('{num}', _, 1)))
                continue

            try:
                if sub in self.found_subs:
                    continue

                self.scan_count_local += 1
                cur_domain = sub + '.' + self.domain

                answers = await self.do_query(j, cur_domain)
                if answers:
                    self.found_subs.add(sub)
                    ips = ', '.join(sorted([answer.address for answer in answers]))
                    invalid_ip_found = False
                    for answer in answers:
                        if answer.address in ['1.1.1.1', '127.0.0.1', '0.0.0.0', '0.0.0.1']:
                            invalid_ip_found = True
                    if invalid_ip_found:
                        continue
                    if self.options.i and is_intranet(answers[0].host):
                        continue

                    try:
                        cname = str(answers.canonical_name)[:-1]
                        if cname != cur_domain and cname.endswith(self.domain):
                            cname_sub = cname[:len(cname) - len(self.domain) - 1]    # new sub
                            if cname_sub not in self.found_subs and cname_sub not in self.normal_names_set:
                                await self.queue.put((0, cname_sub))
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
                        async with timeout(10.0):
                            await self.check_https_alt_names(cur_domain)

                    try:
                        self.scan_count_local += 1
                        await self.do_query(j, 'lijiejie-test-not-existed.' + cur_domain)

                    except dns.resolver.NXDOMAIN as e:
                        if self.queue.qsize() < 20000:
                            for _ in self.next_subs:
                                await self.queue.put((0, _ + '.' + sub))
                        else:
                            await self.queue.put((1, '{next_sub}.' + sub))
                    except Exception as e:
                        continue

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                pass
            except dns.resolver.NoNameservers as e:
                self.no_server_subs[sub] = self.no_server_subs.get(sub, 0) + 1
                if self.no_server_subs[sub] <= 3:
                    await self.queue.put((0, sub))    # Retry again
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as e:
                self.timeout_subs[sub] = self.timeout_subs.get(sub, 0) + 1
                if self.timeout_subs[sub] <= 3:
                    await self.queue.put((0, sub))    # Retry again
            except Exception as e:
                if str(type(e)).find('asyncio.exceptions.TimeoutError') < 0:
                    with open('errors.log', 'a') as errFile:
                        errFile.write('[%s] %s\n' % (type(e), str(e)))

    async def async_run(self):
        await self.load_sub_names()
        tasks = [self.scan(i) for i in range(self.options.threads)]
        tasks.insert(0, self.update_counter())
        await asyncio.gather(*tasks)

    def run(self):
        loop = asyncio.get_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.async_run())
