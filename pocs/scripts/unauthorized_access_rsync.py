#!/usr/bin/env python
# -*- encoding: utf-8 -*-

# rsync 未授权访问
import socket
from lib.common.utils import save_script_result


ports_to_check = 873    # 默认扫描端, 会扫描端口是否开放


def do_check(self, url):
    if url != '/':
        return
    port = 873
    # 非标准端口，不需要检查端口是否开放
    if self.scheme == 'rsync' and self.port != 873:
        port = self.port
    elif 873 not in self.ports_open:
        return

    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, port))
        s.send(bytes("", 'UTF-8'))
        result = s.recv(1024).decode()
        if "RSYNCD" in result:
            save_script_result(self, '', 'rsync://%s:%s' % (self.host, port), 'Rsync Unauthorized Access')
    except Exception as e:
        s.close()

