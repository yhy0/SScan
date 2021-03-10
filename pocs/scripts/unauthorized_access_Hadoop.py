#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

# Hadoop 未授权访问

import requests
from lib.common.utils import save_script_result
from lib.config.setting import default_headers

ports_to_check = 50070    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 50070
    if self.scheme == 'Hadoop' and self.port != 50070:    # 非标准端口
        port = self.port
    elif 50070 not in self.ports_open:
        return

    try:
        url = 'http://' + self.host + ':' + str(port) + '/dfshealth.html'
        r = requests.get(url, timeout=5, verify=False, headers = default_headers)
        if 'hadoop.css' in r.content.decode():
            save_script_result(self, '', 'http://%s:%s/dfshealth.html' % (self.host, port), 'Hadoop Unauthorized Accesss')
    except Exception as e:
        pass

