#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

import requests
from requests.adapters import HTTPAdapter
from lib.config import setting
# 禁用安全请求警告
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

'''
连接池
HTTP是建立在TCP上面的，一次HTTP请求要经历TCP三次握手阶段，
然后发送请求，得到相应，最后TCP断开连接。如果我们要发出多个HTTP请求，
每次都这么搞，那每次要握手、请求、断开，就太浪费了，如果是HTTPS请求，就更加浪费了，
每次HTTPS请求之前的连接多好几个包（不包括ACK的话会多4个）。
所以如果我们在TCP或HTTP连接建立之后，可以传输、传输、传输，就能省很多资源。
于是就有了“HTTP（S）连接池”的概念。
'''


def conn_pool():
    session = requests.Session()
    session.keep_alive = False
    session.headers = setting.default_headers
    # 创建一个适配器，连接池的数量pool_connections, 最大数量pool_maxsize, 失败重试的次数max_retries

    '''
    pool_connections – 缓存连接 缓存的 urllib3 连接池个数， 指定的不是连接的数量，而是连接池的数量，一般默认的10就够用了。
    pool_maxsize – 指定的才是每个pool中最大连接数量
    max_retries (int) – 每次连接的最大失败重试次数，只用于 DNS 查询失败，socket 连接或连接超时，
    默认情况下         
    Requests 不会重试失败的连接，如果你需要对请求重试的条件进行细粒度的控制，可以引入 urllib3 的 Retry 类
    pool_block – 连接池是否应该为连接阻塞
    '''

    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=100, pool_block=False)
    # 告诉requests，http协议和https协议都使用这个适配器
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    # 设置为False, 主要是HTTPS时会报错
    session.verify = False

    # 禁止使用环境系统代理
    session.trust_env = False

    return session
