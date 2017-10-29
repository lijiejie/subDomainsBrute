#!/usr/bin/env python3
#coding:utf-8

'''
这个脚本接受一个 subdomain 扫描结果
打开文件的每一行，取出其中的域名，检测当前网络是否能访问
标题可能会乱码，这里并没有处理
'''

import requests
import sys
from bs4 import BeautifulSoup

FILENAME = sys.argv[1]
def highlight(input_string):
    "高亮输出"
    OKGREEN = '\x1b[92m'
    ENDC = '\x1b[0m'
    info = u'{}{}{}'.format(OKGREEN,input_string,ENDC)
    return(info)


class CheckIp():
    """检测子域名能否访问，如果可以则尝试获取标题
    """
    def __init__(self,host,timeout=5):
        self.host = host
        self.timeout = timeout
        self.info = ''

    def format_host(self):
        _host = self.host.strip()
        for x in [' ','\t']:
            if x in _host:
                _host = _host.split(x)[0]
                break
        self.host = _host
        if '://' in self.host:
            pass
        elif ',' in self.host:
            self.host = self.host.replace(',','')
        else:
            self.host = 'http://'+self.host

    def sendRequests(self):
        "发送请求，判断结果"
        self.format_host()
        try:
            req = requests.get(self.host,timeout = self.timeout)
            req.encoding =req.apparent_encoding
            #尝试获取网页标题
            try:
                soup = BeautifulSoup(req.text,'lxml')
                self.info = soup.title.text.strip()
            except:
                pass
            self.code = req.status_code
            return(req.status_code)
        except requests.Timeout:
            print('[-]{} Timeout'.format(self.host))
            return(0)
        except requests.exceptions.ConnectionError:
            print('[-]{} connect refused'.format(self.host))
    def run(self):
        if self.sendRequests():
            info = u"[+]{} {} {}".format(self.code,self.host,self.info)
            print(highlight(info))


with open(FILENAME) as f:
    for line in f.readlines():
        line = line.strip()
        a = CheckIp(line)
        a.run()
