#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

# FTP 未授权访问

import ftplib
from lib.common.utils import save_script_result

ports_to_check = 21    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 21
    if self.scheme == 'ftp' and self.port != 21:    # 非标准端口
        port = self.port
    elif 21 not in self.ports_open:
        return

    try:
        ftp = ftplib.FTP()
        ftp.connect(self.host, port, timeout=5)  # 连接的ftp sever和端口
        ftp.login('anonymous', 'Aa@12345678')
        save_script_result(self, '', 'ftp://%s:%s/' % (self.host, port), 'FTP Unauthorized Accesss')
    except Exception as e:
        pass

