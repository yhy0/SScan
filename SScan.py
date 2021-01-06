#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

import fire
import os
from datetime import datetime
from config.log import logger
import glob
import re
import time
from lib.common.TestProxy import testProxy
from config.banner import SScan_banner
from lib.common.report import save_report
from lib.common.common import prepare_targets, scan_process
from config import setting
from lib.common.utils import clear_queue

import multiprocessing


class SScan(object):
    """
    InfoScan help summary page\n
    InfoScan is a Sensitive information detection and vulnerability scanning program

    Example:
        python3 SScan.py version
        python3 SScan.py --host example.com run
        python3 SScan.py --file domains.txt run

        :param str    host:              HOST1 HOST2 ... Scan several hosts from command line
        :param str    file:               Load new line delimited targets from TargetFile
        :param str    dire:              Load all *.txt files from TargetDirectory
        :param int    network:           Scan all Target/MASK neighbour hosts, should be an int between 8 and 31
        :param int    t:                 Num of scan threads for each scan process, 10 by default
        :param tuple  rule:              RuleFileName1,RuleFileName2,... Import specified rules files only.
        :param bool   crawl:             crawling, crawl <a href='...'>  (default True)
        :param bool   checkcdn:          Check the CDN and skip the IP where the CDN exists (default True)
        :param bool   full:              Process all sub directories /x/y/z/，/x/ /x/y/ (default True)
        :param str    script:            ScriptName1,ScriptName2,...
        :param bool   script_only:       Scan with user scripts only
        :param bool   noscripts:         Disable all scripts (default False)
        :param bool   debug:             Show verbose debug info (default False)
        :param bool   browser:           Do not open web browser to view report (default True)

    """

    def __init__(self, host=None, file=None, dire="", network=32, t=10, rule=None,
                 full=True, script=None, noscripts=False, debug=True, crawl=True,
                 browser=True, script_only=False, checkcdn=True):
        self.host = host
        self.file = file
        self.rule_files = []
        self.script_files = []
        self.dire = dire
        self.network = network
        self.t = t
        self.rule = rule
        self.crawl = crawl
        self.checkcdn = checkcdn
        self.fileull = full
        self.scripts_only = script_only
        self.script = script
        self.no_scripts = noscripts
        self.debug = debug
        self.browser = browser

        if self.file:
            self.input_files = [self.file]
        elif self.dire:
            self.input_files = glob.glob(self.dire + '/*.txt')
        elif self.host:
            self.input_files = [self.host]
        self.require_no_http = True  # 所有插件都不依赖 HTTP 连接池
        self.require_index_doc = False  # 插件需要请求首页
        self.require_ports = set()  # 插件扫描所需端口

    # 加载相关配置
    def config_param(self):
        """
        Config parameter
        """
        if self.dire:
            self.dire = glob.glob(self.dire + '/*.txt')

        if self.rule is None:
            self.rule_files = glob.glob('rules/*.txt')
        else:
            if isinstance(self.rule, str):
                rule = self.rule.split()
            else:
                rule = self.rule
            for rule_name in rule:
                if not rule_name.endswith('.txt'):
                    rule_name += '.txt'
                if not os.path.exists('rules/%s' % rule_name):
                    logger.log('FATAL', 'Rule file not found: %s' % rule_name)
                    exit(-1)
                self.rule_files.append(f'rules/{rule_name}')

        if not self.no_scripts:
            if self.script is None:
                self.script_files = glob.glob('scripts/*.py')
            else:
                if isinstance(self.script, str):
                    script = self.script.split()
                else:
                    script = self.script
                for script_name in script:
                    if not script_name.lower().endswith('.py'):
                        script_name += '.py'
                    if not os.path.exists('scripts/%s' % script_name):
                        logger.log('FATAL', 'Rule file not found: %s' % script_name)
                        exit(-1)

                    self.script_files.append('scripts/%s' % script_name)
            pattern = re.compile(r'ports_to_check.*?\\=(.*)')

            for _script in self.script_files:
                with open(_script) as f:
                    content = f.read()
                    if content.find('self.http_request') > 0 or content.find('self.session') > 0:
                        self.require_no_http = False  # 插件依赖HTTP连接池
                    if content.find('self.index_') > 0:
                        self.require_no_http = False
                        self.require_index_doc = True
                    # 获取插件需要的端口
                    m = pattern.search(content)
                    if m:
                        m_str = m.group(1).strip()
                        if m_str.find('#') > 0:  # 去掉注释
                            m_str = m_str[:m_str.find('#')]
                        if m_str.find('[') < 0:
                            if int(m_str) not in self.require_ports:
                                self.require_ports.add(int(m_str))
                        else:
                            for port in eval(m_str):
                                if port not in self.require_ports:
                                    self.require_ports.add(int(port))

    # 检查命令行输入
    def check_param(self):
        """
        Check parameter
        """
        if not (self.file or self.dire or self.host):
            msg = '\nself missing! One of following self should be specified  \n' \
                  '           \t--f TargetFile \n' \
                  '           \t--d TargetDirectory \n' \
                  '           \t--host www.host1.com www.host2.com 8.8.8.8'
            logger.log('FATAL', msg)
            exit(-1)
        if self.file and not os.path.isfile(self.file):
            logger.log('FATAL', 'TargetFile not found: %s' % self.file)
            exit(-1)

        if self.dire and not os.path.isdir(self.dire):
            logger.log('FATAL', 'TargetDirectory not found: %s' % self.dire)
            exit(-1)

        self.network = int(self.network)
        if not (8 <= self.network <= 32):
            logger.log('FATAL', 'Network should be an integer between 24 and 31')
            exit(-1)

    def main(self):
        q_targets = multiprocessing.Manager().Queue()  # targets Queue

        q_targets_list = []
        q_results = multiprocessing.Manager().Queue()  # log Queue

        for input_file in self.input_files:
            # 读取目标
            if self.host:
                target_list = self.host.replace(',', ' ').strip().split()

            elif self.file or self.dire:
                with open(input_file) as inFile:
                    target_list = inFile.readlines()

            try:
                import threading
                # 实时生成报告
                target_count = len(target_list)  # 目标数
                # 生成报告，管理标准输出
                threading.Thread(target=save_report, args=(self, q_results, input_file, target_count)).start()

                clear_queue(q_results)
                clear_queue(q_targets)

                start_time = time.time()

                # 根据电脑 CPU 的内核数量, 创建相应的进程池
                # count = multiprocessing.cpu_count()
                count = 16
                # 少量目标，至多创建2倍扫描进程
                if len(target_list) * 2 < count:
                    count = len(target_list) * 2
                pool = multiprocessing.Pool(count)
                setting.tasks_count.value = 0

                for i in range(0, len(target_list), count):
                    target = target_list[i:i + count]
                    pool.apply_async(prepare_targets, args=(target, q_targets, self, count))

                pool.close()
                pool.join()

                time.sleep(1.0)

                while True:
                    if not q_targets.empty():
                        q_targets_list.append(q_targets.get())
                    else:
                        break

                logger.log("INFOR", f'Targets process all done in %.1f seconds!' % (time.time() - start_time))

                # q_targets.get() {'scheme': 'https', 'host': '127.0.0.1', 'port': 443, 'path': '', 'ports_open': [80, 443], 'is_neighbor': 0}

                if len(target_list) * 2 < count:
                    count = len(target_list) * 2

                pool = multiprocessing.Pool(count)
                logger.log('INFOR', f'{count} scan process created.')

                for target in q_targets_list:
                    pool.apply_async(scan_process, args=(target, q_results, self))

                pool.close()
                pool.join()

                time.sleep(1.0)

                cost_time = time.time() - start_time
                cost_min = int(cost_time / 60)
                cost_min = '%s min ' % cost_min if cost_min > 0 else ''
                cost_seconds = '%.1f' % (cost_time % 60)
                logger.log('INFOR', f'Scanned {len(q_targets_list)} targets in {cost_min}{cost_seconds} seconds.')

            except KeyboardInterrupt as e:
                setting.stop_me = True
                logger.log('INFOR', 'Scan aborted.')
                exit(-1)
            except Exception as e:
                logger.log('INFOR', '[__main__.exception] %s %s' % (type(e), str(e)))
            setting.stop_me = True

    def print(self):
        """
        InfoScan running entrance
        :return: All subdomain log
        :rtype: list
        """
        print(SScan_banner)
        dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f'[*] Starting InfoScan @ {dt}\n')
        self.check_param()
        self.config_param()
        if self.no_scripts:
            logger.log('INFOR', '* Scripts scan was disabled.')
        if self.require_ports:
            logger.log('INFOR', '* Scripts scan port check: %s' % ','.join([str(x) for x in self.require_ports]))

    def run(self):
        self.print()
        # 网络连通性检查
        # testProxy(cmd, 1)
        # if testProxy(1):
        self.main()

    @staticmethod
    def version():
        """
        Print version information and exit
        """
        print(SScan_banner)
        exit(0)


if __name__ == '__main__':
    fire.Fire(SScan)
