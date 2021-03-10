#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

# JBoss 未授权访问

import requests
from lib.common.utils import save_script_result

ports_to_check = 8080    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 8080
    if self.scheme == 'jenkins' and self.port != 8080:    # 非标准端口
        port = self.port
    elif 8080 not in self.ports_open:
        return
    try:
        url = 'http://' + self.host + ':' + str(port) + '/jmx-console/HtmlAdaptor?action=displayMBeans'
        r = requests.get(url, timeout=5)
        if 'JBoss JMX Management Console' in r.content.decode() and r.status_code == 200 and 'jboss' in r.content.decode():
            save_script_result(self, '', 'http://%s:%s/jmx-console/HtmlAdaptor?action=displayMBeans' % (self.host, port), 'JBoss Unauthorized Accesss')
    except Exception as e:
        pass
