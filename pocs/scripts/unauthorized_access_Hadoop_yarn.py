#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

# Hadoop yarn 未授权访问

import requests
from lib.common.utils import save_script_result
from lib.config.setting import default_headers
ports_to_check = 8088    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 8088
    if self.scheme == 'Hadoop yarn' and self.port != 8088:    # 非标准端口
        port = self.port
    elif 8088 not in self.ports_open:
        return

    try:
        url = 'http://' + self.host + ':' + str(port) + '/ws/v1/cluster/info'
        r = requests.get(url, timeout=5, verify=False, headers = default_headers)
        if 'resourceManagerVersionBuiltOn' in r.content.decode() or 'hadoopVersion'in r.content.decode():
            save_script_result(self, '', 'http://%s:%s/ws/v1/cluster/info' % (self.host, port), 'Hadoop yarn Unauthorized Accesss')
    except Exception as e:
        pass

