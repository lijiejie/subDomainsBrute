# common functions

import sys
import os
import asyncio
import aiodns
from .common import print_msg, load_next_sub, get_out_file_name, user_abort, get_sub_file_path


async def test_server_python3(server, dns_servers):
    resolver = aiodns.DNSResolver()
    try:
        resolver.nameservers = [server]
        answers = await resolver.query('public-dns-a.baidu.com', 'A')    # an existed domain
        if answers[0].host != '180.76.76.76':
            raise Exception('Incorrect DNS response')
        try:
            await resolver.query('test.bad.dns.lijiejie.com', 'A')    # non-existed domain
            with open('bad_dns_servers.txt', 'a') as f:
                f.write(server + '\n')
            print_msg('[+] Bad DNS Server found %s' % server)
        except Exception as e:
            dns_servers.append(server)
        print_msg('[+] Server %s < OK >   Found %s' % (server.ljust(16), len(dns_servers)))
    except Exception as e:
        print_msg('[+] Server %s <Fail>   Found %s' % (server.ljust(16), len(dns_servers)))


async def async_load_dns_servers(servers_to_test, dns_servers):
    tasks = []
    for server in servers_to_test:
        task = test_server_python3(server, dns_servers)
        tasks.append(task)
    await asyncio.gather(*tasks)


def load_dns_servers():
    print_msg('[+] Validate DNS servers', line_feed=True)
    dns_servers = []

    servers_to_test = []
    for server in open('dict/dns_servers.txt').readlines():
        server = server.strip()
        if server and not server.startswith('#'):
            servers_to_test.append(server)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_load_dns_servers(servers_to_test, dns_servers))
    # loop.close()

    server_count = len(dns_servers)
    print_msg('\n[+] %s DNS Servers found' % server_count, line_feed=True)
    if server_count == 0:
        print_msg('[ERROR] No valid DNS Server !', line_feed=True)
        sys.exit(-1)
    return dns_servers


def load_next_sub(options):
    next_subs = []
    _file = 'dict/next_sub_full.txt' if options.full_scan else 'dict/next_sub.txt'
    with open(_file) as f:
        for line in f:
            sub = line.strip()
            if sub and sub not in next_subs:
                tmp_set = {sub}
                while tmp_set:
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
    return next_subs


def get_out_file_name(target, options):
    if options.output:
        outfile = options.output
    else:
        _name = os.path.basename(options.file).replace('subnames', '')
        if _name != '.txt':
            _name = '_' + _name
        outfile = target + _name
    return outfile


async def async_wildcard_test(domain, dns_servers, level=1):
    try:
        r = aiodns.DNSResolver()
        r.nameservers = dns_servers
        answers = await r.query('lijiejie-not-existed-test.%s' % domain, 'A')
        ips = ', '.join(sorted([answer.host for answer in answers]))
        if level == 1:
            print('any-sub.%s\t%s' % (domain.ljust(30), ips))
            await async_wildcard_test('any-sub.%s' % domain, dns_servers, 2)
        elif level == 2:
            sys.exit(0)
    except Exception as e:
        return domain


def wildcard_test(domain, dns_servers):
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(asyncio.gather(async_wildcard_test(domain, dns_servers, level=1)))[0]

