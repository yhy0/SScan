#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

# docker registry api 未授权访问

import requests
from lib.common.utils import save_script_result

ports_to_check = 30000    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 30000
    if self.scheme == 'docker api' and self.port != 30000:    # 非标准端口
        port = self.port
    elif 30000 not in self.ports_open:
        return

    try:
        r0 = requests.get(f"http://{self.host}:{port}/v2/_catalog", timeout=5, verify=False)

        if "repositories" in r0.text:
            save_script_result(self, '', 'http://%s:%s/v2/_catalog' % (self.host, port), 'docker registry api Unauthorized Accesss')
            return
        r = requests.get(f"http://{self.host}:{port}/v1/_catalog", timeout=5, verify=False)
        if "repositories" in r.text:
            save_script_result(self, '', 'http://%s:%s/v1/_catalog' % (self.host, port), 'docker registry api Unauthorized Accesss')
        return

    except Exception as e:
        pass


