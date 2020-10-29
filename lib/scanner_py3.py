# -*- encoding: utf-8 -*-

import platform
import re
import time
import asyncio
import aiodns
from asyncio import PriorityQueue
from .common import is_intranet
import random


if platform.system() == 'Windows':
    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class SubNameBrute(object):
    def __init__(self, *params):
        self.domain, self.options, self.process_num, self.dns_servers, self.next_subs, \
            self.scan_count, self.found_count, self.queue_size_array, tmp_dir = params
        self.dns_count = len(self.dns_servers)
        self.scan_count_local = 0
        self.found_count_local = 0
        self.resolvers = [aiodns.DNSResolver(tries=1) for _ in range(self.options.threads)]
        self.queue = PriorityQueue()
        self.ip_dict = {}
        self.found_subs = set()
        self.timeout_subs = {}
        self.count_time = time.time()
        self.outfile = open('%s/%s_part_%s.txt' % (tmp_dir, self.domain, self.process_num), 'w')
        self.normal_names_set = set()
        self.lock = asyncio.Lock()
        self.loop = None
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

    async def scan(self, j):
        self.resolvers[j].nameservers = [self.dns_servers[j % self.dns_count]]
        if self.dns_count > 1:
            while True:
                s = random.choice(self.resolvers)
                if s != self.dns_servers[j % self.dns_count]:
                    self.resolvers[j].nameservers.append(s)
                    break
        while True:
            try:
                if time.time() - self.count_time > 1.0:
                    async with self.lock:
                        self.scan_count.value += self.scan_count_local
                        self.scan_count_local = 0
                        self.queue_size_array[self.process_num] = self.queue.qsize()
                        if self.found_count_local:
                            self.found_count.value += self.found_count_local
                            self.found_count_local = 0
                        self.count_time = time.time()

                try:
                    brace_count, sub = self.queue.get_nowait()
                    self.threads_status[j] = '1'
                except asyncio.queues.QueueEmpty as e:
                    self.threads_status[j] = '0'
                    await asyncio.sleep(0.5)
                    if '1' not in self.threads_status:
                        break
                    else:
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
            except Exception as e:
                import traceback
                print(traceback.format_exc())
                break

            try:

                if sub in self.found_subs:
                    continue

                self.scan_count_local += 1
                cur_domain = sub + '.' + self.domain
                # print('Query %s' % cur_domain)
                answers = await self.resolvers[j].query(cur_domain, 'A')

                if answers:
                    self.found_subs.add(sub)
                    ips = ', '.join(sorted([answer.host for answer in answers]))
                    if ips in ['1.1.1.1', '127.0.0.1', '0.0.0.0', '0.0.0.1']:
                        continue
                    if self.options.i and is_intranet(answers[0].host):
                        continue

                    try:
                        self.scan_count_local += 1
                        answers = await self.resolvers[j].query(cur_domain, 'CNAME')
                        cname = answers[0].target.to_unicode().rstrip('.')
                        if cname.endswith(self.domain) and cname not in self.found_subs:
                            cname_sub = cname[:len(cname) - len(self.domain) - 1]    # new sub
                            if cname_sub not in self.normal_names_set:
                                self.found_subs.add(cname)
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
                    try:
                        self.scan_count_local += 1
                        await self.resolvers[j].query('lijiejie-test-not-existed.' + cur_domain, 'A')
                    except aiodns.error.DNSError as e:
                        if e.args[0] in [4]:
                            if self.queue.qsize() < 50000:
                                for _ in self.next_subs:
                                    await self.queue.put((0, _ + '.' + sub))
                            else:
                                await self.queue.put((1, '{next_sub}.' + sub))
                    except Exception as e:
                        pass

            except aiodns.error.DNSError as e:
                if e.args[0] in [1, 4]:
                    pass
                elif e.args[0] in [11, 12]:   # 12 timeout   # (11, 'Could not contact DNS servers')
                    # print('timed out sub %s' % sub)
                    self.timeout_subs[sub] = self.timeout_subs.get(sub, 0) + 1
                    if self.timeout_subs[sub] <= 1:
                        await self.queue.put((0, sub))  # Retry
                else:
                    print(e)
            except asyncio.TimeoutError as e:
                pass
            except Exception as e:
                import traceback
                traceback.print_exc()
                with open('errors.log', 'a') as errFile:
                    errFile.write('[%s] %s\n' % (type(e), str(e)))

    async def async_run(self):
        await self.load_sub_names()
        tasks = [self.scan(i) for i in range(self.options.threads)]
        await asyncio.gather(*tasks)

    def run(self):
        self.loop = asyncio.get_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.async_run())
