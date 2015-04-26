# subDomainsBrute

A simple and fast sub domain brute tool for pentesters

这个脚本的主要目标是发现其他工具无法探测到的域名. 比如大家常用的Google，aizhan，fofa。

##Dependencies
First you need install [dnspython](http://www.dnspython.org/kits/1.12.0/) to do DNS query

## Improvements
* 用小字典递归地发现三级域名，四级域名、五级域名等不容易被探测到的域名
* 字典较为全面，小字典就包括3万多条，大字典多达8万条
* 默认使用114DNS、百度DNS、阿里DNS这几个快速又可靠的公共DNS进行查询，可随时修改配置文件添加你认为可靠的DNS服务器
* 自动筛选泛解析的域名，当前规则是： 超过10个域名指向同一IP，则此后发现的其他指向该IP的域名将被丢弃
* 整体速度还过得去，在我的PC上，每秒稳定扫描100到200个域名（10个线程）

##Usage
```
Usage: subDomainsBrute.py [options] target

Options:
  -h, --help            show this help message and exit
  -t THREADS_NUM, --threads=THREADS_NUM
                        Number of threads. default = 10
  -f NAMES_FILE, --file=NAMES_FILE
                        Dict file used to brute sub names
  -o OUTPUT, --output=OUTPUT
                        Output file name. default is {target}.txt
```

Output file could be like: [http://www.lijiejie.com/wp-content/uploads/2015/04/baidu.com_.txt](http://www.lijiejie.com/wp-content/uploads/2015/04/baidu.com_.txt)

my[at]lijiejie.com ([http://www.lijiejie.com](http://www.lijiejie.com))