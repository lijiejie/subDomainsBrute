# common functions

import sys
import os
import asyncio
import dns.asyncresolver
from .common import print_msg, load_next_sub, get_out_file_name, user_abort, get_sub_file_path, root_path


async def test_server_python3(server, dns_servers):
    resolver = dns.asyncresolver.Resolver(configure=False)
    try:
        resolver.nameservers = [server]
        answers = await resolver.resolve('public-dns-a.baidu.com', 'A', lifetime=5)    # an existed domain
        if answers[0].address != '180.76.76.76':
            raise Exception('Incorrect DNS response')
        try:
            await resolver.resolve('test.bad.dns.lijiejie.com', 'A', lifetime=5)    # non-existed domain
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
    for server in open(os.path.join(root_path, 'dict/dns_servers.txt')).readlines():
        server = server.strip()
        if server and not server.startswith('#'):
            servers_to_test.append(server)


    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_load_dns_servers(servers_to_test, dns_servers))

    server_count = len(dns_servers)
    print_msg('\n[+] %s DNS Servers found' % server_count, line_feed=True)
    if server_count == 0:
        print_msg('[ERROR] No valid DNS Server !', line_feed=True)
        sys.exit(-1)
    return dns_servers


async def async_wildcard_test(domain, dns_servers, level=1):
    try:
        r = dns.asyncresolver.Resolver()
        r.nameservers = dns_servers
        answers = await r.resolve('lijiejie-not-existed-test.%s' % domain, 'A', lifetime=10)
        ips = ', '.join(sorted([answer.address for answer in answers]))
        if level == 1:
            print('any-sub.%s\t%s' % (domain.ljust(30), ips))
            await async_wildcard_test('any-sub.%s' % domain, dns_servers, 2)
        elif level == 2:
            print('\nUse -w to enable force scan wildcard domain')
            sys.exit(0)
    except Exception as e:
        return domain


def wildcard_test(domain, dns_servers):
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(asyncio.gather(async_wildcard_test(domain, dns_servers, level=1)))[0]
