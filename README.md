# subDomainsBrute

A simple and fast sub domain brute tool for pentesters.

这个脚本的主要目标是发现其他工具无法探测到的域名. 比如大家常用的Google，aizhan，fofa。

##Change Log
* 字典统一到dict文件夹下
* 精简二级域名字典，丰富三四域名字典
* 增加-i参数，忽略指向内网IP域名
* 默认由10线程调整为30线程，但增加了超时重试

##Dependencies
First you need to install [dnspython](http://www.dnspython.org/kits/1.12.0/) to do DNS query
> pip install dnspython

## Improvements
* 用小字典递归地发现三级域名，四级域名、五级域名等不容易被探测到的域名
* 字典较为丰富，小字典就包括1万5千条，大字典多达6万3千条
* 默认使用114DNS、百度DNS、阿里DNS这几个快速又可靠的Public DNS查询，可修改配置文件添加DNS服务器
* 自动去重泛解析的域名，当前规则： 超过2个域名指向同一IP，则此后发现的其他指向该IP的域名将被丢弃
* 速度尚可，在我的PC上，每秒稳定扫描约3百个域名（30个线程）

##Usage
```
Usage: subDomainsBrute.py [options] target.com

Options:
  -h, --help            show this help message and exit
  -t THREADS_NUM, --threads=THREADS_NUM
                        Number of threads. default = 30
  -f NAMES_FILE, --file=NAMES_FILE
                        Dict file used to brute sub names
  -i, --ignore-intranet
                        Ignore domains pointed to private IPs.
  -o OUTPUT, --output=OUTPUT
                        Output file name. default is {target}.txt

```

Output file could be like: [http://www.lijiejie.com/wp-content/uploads/2015/04/baidu.com_.txt](http://www.lijiejie.com/wp-content/uploads/2015/04/baidu.com_.txt)

my[at]lijiejie.com ([http://www.lijiejie.com](http://www.lijiejie.com))