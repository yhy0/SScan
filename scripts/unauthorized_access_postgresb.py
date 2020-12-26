#!/usr/bin/python
# -*- encoding: utf-8 -*-

# PostgreSQL 空口令访问
import psycopg2
from lib.common.utils import save_script_result


ports_to_check = 5432    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 5432
    if self.scheme == 'PostgreSQL' and self.port != 5432:    # 非标准端口
        port = self.port
    elif 5432 not in self.ports_open:
        return

    try:
        conn = psycopg2.connect(database="postgres", user="postgres", password="", host=self.host, port=port)
        save_script_result(self, '', 'mysql://%s:%s' % (self.host, port), '', 'PostgreSQL empty password')
    except Exception as e:
        pass
