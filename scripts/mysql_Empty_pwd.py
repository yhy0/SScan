#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

# mysql空口令

import pymysql
from lib.common.utils import save_script_result


ports_to_check = 3306    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 3306
    if self.scheme == 'mysql' and self.port != 3306:    # 非标准端口
        port = self.port
    elif 3306 not in self.ports_open:
        return

    try:
        conn = pymysql.connect(host=self.host, user='root', password='', charset='utf8', autocommit=True)
        conn.close()
        save_script_result(self, '', 'mysql://%s:%s' % (self.host, port), '', 'Mysql empty password')
    except Exception as e:
        pass
