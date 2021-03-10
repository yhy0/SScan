#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

# CouchDB 未授权访问

import requests
from lib.common.utils import save_script_result
from lib.config.setting import default_headers

ports_to_check = 5984    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 5984
    if self.scheme == 'CouchDB' and self.port != 5984:    # 非标准端口
        port = self.port
    elif 5984 not in self.ports_open:
        return

    try:
        url = 'http://' + self.host + ':' + str(port) + '/_utils/'
        r = requests.get(url, timeout=5, verify=False, headers=default_headers)
        if 'couchdb-logo' in r.content.decode():
            save_script_result(self, '', 'http://%s:%s/_utils/' % (self.host, port), 'CouchDB Unauthorized Accesss')
    except Exception as e:
        pass

