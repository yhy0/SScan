#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

import requests
from config import setting
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
    # 创建一个适配器，连接池的数量pool_connections, 最大数量pool_maxsize, 失败重试的次数max_retries
    '''
    pool_connections – 缓存的 urllib3 连接池个数
    pool_maxsize – 连接池中保存的最大连接数
    max_retries (int) – 每次连接的最大失败重试次数，只用于 DNS 查询失败，socket 连接或连接超时，
    默认情况下         
    Requests 不会重试失败的连接，如果你需要对请求重试的条件进行细粒度的控制，可以引入 urllib3 的 Retry 类
    pool_block – 连接池是否应该为连接阻塞
    '''
    adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=1, pool_block=False)
    # 告诉requests，http协议和https协议都使用这个适配器
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    # 设置为False, 主要是HTTPS时会报错
    session.verify = False

    # user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36'
    # user_agent = default_headers

    # 公共的请求头设置
    session.heads = setting.default_headers

    return session
