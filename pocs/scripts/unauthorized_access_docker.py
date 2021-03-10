#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

# docker api 未授权访问

import requests
from lib.common.utils import save_script_result
from lib.config.setting import default_headers

ports_to_check = 2375    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 2375
    if self.scheme == 'docker api' and self.port != 2375:    # 非标准端口
        port = self.port
    elif 2375 not in self.ports_open:
        return

    try:
        url = 'http://' + self.host + ':' + str(port) + '/version'
        r = requests.get(url, timeout=5, verify=False, headers = default_headers)
        if 'ApiVersion' in r.content.decode():
            save_script_result(self, '', 'http://%s:%s/version' % (self.host, port), 'docker api Unauthorized Accesss')
    except Exception as e:
        pass

