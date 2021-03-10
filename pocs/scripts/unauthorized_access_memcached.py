#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

# memcached 未授权访问

import socket
from lib.common.utils import save_script_result

ports_to_check = 11211    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 11211
    if self.scheme == 'memcached' and self.port != 11211:    # 非标准端口
        port = self.port
    elif 11211 not in self.ports_open:
        return
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, port))
        s.send(bytes('stats\r\n', 'UTF-8'))
        if 'version' in s.recv(1024).decode():
            save_script_result(self, '', 'memcached://%s:%s' % (self.host, port), 'Memcached Unauthorized Accesss')
        s.close()
    except Exception as e:
        pass
    finally:
        s.close()
