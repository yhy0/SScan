#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

# elasticsearch 未授权访问

import requests
from lib.common.utils import save_script_result


ports_to_check = 9200    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 9200
    if self.scheme == 'elasticsearch' and self.port != 9200:    # 非标准端口
        port = self.port
    elif 9200 not in self.ports_open:
        return
    try:
        url = 'http://' + self.host + ':' + str(port) + '/_cat'
        r = requests.get(url, timeout=5)
        if '/_cat/master' in r.content.decode():
            save_script_result(self, '', 'http://%s:%s/_cat' % (self.host, port), 'Elasticsearch Unauthorized Accesss')
    except Exception as e:
        pass
