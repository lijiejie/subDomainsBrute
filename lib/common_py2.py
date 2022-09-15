# common functions

import sys
import os
from gevent.pool import Pool
import dns.resolver
from .common import print_msg, load_next_sub, get_out_file_name, user_abort, get_sub_file_path, root_path


def test_server(server, dns_servers):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.lifetime = resolver.timeout = 5.0
    try:
        resolver.nameservers = [server]
        answers = resolver.query('public-dns-a.baidu.com')    # an existed domain
        if answers[0].address != '180.76.76.76':
            raise Exception('Incorrect DNS response')
        try:
            resolver.query('test.bad.dns.lijiejie.com')    # non-existed domain
            with open('bad_dns_servers.txt', 'a') as f:
                f.write(server + '\n')
            print_msg('[+] Bad DNS Server found %s' % server)
        except Exception as e:
            dns_servers.append(server)
            print_msg('[+] Server %s < OK >   Found %s' % (server.ljust(16), len(dns_servers)))
    except Exception as e:
        print_msg('[+] Server %s <Fail>   Found %s' % (server.ljust(16), len(dns_servers)))


def load_dns_servers():
    print_msg('[+] Validate DNS servers', line_feed=True)
    dns_servers = []
    pool = Pool(5)
    for server in open(os.path.join(root_path, 'dict/dns_servers.txt')).readlines():
        server = server.strip()
        if server and not server.startswith('#'):
            pool.apply_async(test_server, (server, dns_servers))
    pool.join()

    server_count = len(dns_servers)
    print_msg('\n[+] %s DNS Servers found' % server_count, line_feed=True)
    if server_count == 0:
        print_msg('[ERROR] No valid DNS Server !', line_feed=True)
        sys.exit(-1)
    return dns_servers


def wildcard_test(domain, dns_servers, level=1):
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = dns_servers
        answers = r.query('lijiejie-not-existed-test.%s' % domain)
        ips = ', '.join(sorted([answer.address for answer in answers]))
        if level == 1:
            print('any-sub.%s\t%s' % (domain.ljust(30), ips))
            wildcard_test('any-sub.%s' % domain, dns_servers, 2)
        elif level == 2:
            print('\nUse -w to enable force scan wildcard domain')
            sys.exit(0)
    except Exception as e:
        return domain
