#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

import requests
import asyncio
from concurrent.futures import ThreadPoolExecutor
# 忽略警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import importlib
from yarl import URL
import traceback
import re
import time
import glob
import os
from bs4 import BeautifulSoup

from config.log import logger
from lib.common.utils import get_domain_sub, cal_depth, get_html
from config import setting
from lib.common.connectionPool import conn_pool


class Scanner(object):
    def __init__(self, timeout=600, args=None):

        self.args = args
        self.start_time = time.time()
        self.time_flag = True
        self.links_limit = 100  # max number of folders to scan
        self._init_rules()
        self._init_scripts()
        self.timeout = timeout  # 每个目标的最大扫描分钟，默认为10分钟
        self.session = conn_pool()  # 使用连接池

        self.url_list = list()  # all urls to scan 任务处理队列
        self.urls_processed = set()     # processed urls
        self.urls_enqueued = set()      # entered queue urls
        self.urls_crawled = set()

        self._302_url = set()  # 302 跳转后，页面符合黑名单规则的

        self.results = {}
        self._404_status = -1

        self.index_status, self.index_headers, self.index_html_doc = None, {}, ''
        self.scheme, self.host, self.port, self.path = None, None, None, None
        self.domain_sub = ''
        self.base_url = ''
        self.max_depth = 0
        self.len_404_doc = 0
        self.has_http = None
        self.ports_open = None
        self.ports_closed = None
        self.no_scripts = None
        self.status_502_count = 0
        self.flag = False
        self.check = True  # 当页面502 时，标记为False，不再检查

    def reset_scanner(self):
        self.start_time = time.time()
        self.url_list.clear()
        self.urls_processed.clear()
        self.urls_enqueued.clear()
        self.urls_crawled.clear()
        self.results.clear()
        self._404_status = -1
        self.index_status, self.index_headers, self.index_html_doc = None, {}, ''
        self.scheme, self.host, self.port, self.path = None, None, None, None
        self.domain_sub = ''
        self.base_url = ''
        self.status_502_count = 0

    # scan from a given URL
    '''
    {'scheme': 'http', 'host': 'baidu.com', 'port': 80, 'path': '', 'has_http': True, 'no_scripts': 1, 'ports_open': {80}, 'ports_closed': set()}
    
    {'scheme': 'http', 'host': '127.0.0.1', 'port': 80, 'path': '', 'ports_open': [80], 'is_neighbor': 0}
    '''
    def init_from_url(self, target):
        self.reset_scanner()
        self.scheme = target['scheme']
        self.host = target['host']
        self.port = target['port']
        self.path = target['path']
        self.has_http = target['has_http']
        self.ports_open = target['ports_open']
        self.no_scripts = target['no_scripts'] if 'no_scripts' in target else 0
        self.domain_sub = get_domain_sub(self.host)     # baidu.com >> baidu
        self.init_final()
        return True

    def init_final(self):
        start_time = time.time()
        if self.scheme == 'http' and self.port == 80 or self.scheme == 'https' and self.port == 443:
            self.base_url = f'{self.scheme}://{self.host}'
        else:
            self.base_url = f'{self.scheme}://{self.host}:{self.port}'

        if self.has_http:
            logger.log('INFOR', f'Scan { self.base_url}')
        else:
            logger.log('INFOR', 'NO_HTTP_Scan %s:%s' % (self.host, self.port) if self.port else 'Scan %s' % self.host)

        # 脚本
        if self.no_scripts != 1:  # 不是重复目标 80 443 跳转的，不需要重复扫描
            # 当前目标disable， 或者 全局开启插件扫描
            if self.args.scripts_only or not self.no_scripts:
                for _ in self.user_scripts:
                    self.url_list.append((_, '/'))

        if not self.has_http or self.args.scripts_only:  # 未发现HTTP服务 或  只依赖插件扫描
            return

        # todo  当url 类似 http://www.example.com , path:'' , max_depth = 1+5=6
        self.max_depth = cal_depth(self, self.path)[1] + 5
        if self.args.check404:
            self._404_status = 404
        else:
            self.check_404_existence()
        if self._404_status == -1:
            logger.log('ALERT', 'HTTP 404 check failed <%s:%s>' % (self.host, self.port))
        elif self._404_status != 404:
            logger.log('ALERT', '%s has no HTTP 404.' % self.base_url)
        _path, _depth = cal_depth(self, self.path)

        # 加入队列
        self.enqueue('/')
        logger.log('INFOR', f'{self.base_url} 目标初始化、404检测、页面a标签爬取共使用 {time.time() - start_time:0.2f} s')

    # 进行http请求
    def http_request(self, url, timeout=20):
        try:
            if not url:
                url = '/'
            if not self.session:
                return -1, {}, ''

            resp = self.session.get(self.base_url + url, allow_redirects=False, timeout=timeout, verify=False)

            headers = resp.headers
            status = resp.status_code

            if status == 502:    # 502出现3次以上，排除该站点
                self.status_502_count += 1
                if self.status_502_count > 3:
                    self.url_list.clear()
                    try:
                        if self.session:
                            self.session.close()
                    except Exception as e:
                        pass
                    self.session = None
                    # logger.log('ALERT', 'Website 502: %s' % self.base_url)
            # 301 永久移动时，重新获取response
            if status == 301:
                target = headers.get('Location')
                try:
                    resp = self.session.get(URL(target, encoded=True), headers=setting.default_headers, allow_redirects=False, timeout=timeout, verify=False)
                    headers = resp.headers
                except Exception as e:
                    logger.log('ERROR', e)
            # 这里禁止重定向， 但有时，网页重定向后才会有东西
            if status == 302:
                new_url = headers["Location"]
                if new_url not in self._302_url:
                    resp = self.session.get(URL(new_url, encoded=True), headers=setting.default_headers, timeout=timeout, verify=False)
                    headers = resp.headers
                    self._302_url.add(new_url)

            html_doc = get_html(headers, resp)
            if self.args.debug:
                logger.log('DEBUG', f'--> {url}  {status, headers}')
            return status, headers, html_doc
        except requests.exceptions.RetryError as e:
            logger.log('ERROR', repr(e))
            return -1, {}, ''
        except requests.exceptions.ConnectionError as e:
            logger.log('ERROR', f'IP可能被封了  {repr(e)}')
            return -1, {}, ''
        except TypeError as e:
            logger.log('ERROR', repr(e))
            return -1, {}, ''
        except Exception as e:
            logger.log('ERROR', f'{repr(e)}   {url}  {self.base_url}')
            return -1, {}, ''

    # 检查状态404是否存在
    def check_404_existence(self):
        try:
            try:
                self._404_status, _, html_doc = self.http_request('/BBScan-404-existence-check')
            except Exception as e:
                logger.log('ALERT', f'HTTP 404 check failed: {self.base_url} {str(e)}')
                self._404_status, _, html_doc = -1, {}, ''
            if self._404_status != 404:
                self.len_404_doc = len(html_doc)
        except Exception as e:
            logger.log('ERROR', f'[Check_404] Exception {self.base_url} {str(e)}')

    # 将检查完的url 加入队列，加载规则和脚本  这里的url 是个相对路径，example: http://www.baidu.com/url
    def enqueue(self, url):
        try:
            url = str(url)
        except Exception as e:
            return False
        try:
            # 当url中存在数字时，将url中的数字替换成 {num}  test1.baidu.com >> test{num}.baidu.com
            # todo 看不懂在干嘛
            url_pattern = re.sub(r'\d+', '{num}', url)

            if url_pattern in self.urls_processed or len(self.urls_processed) >= self.links_limit:
                return False

            self.urls_processed.add(url_pattern)
            # logger.log('INFOR', 'Entered Queue: %s' % url_pattern)
            if self.args.crawl:  # 爬取网站的 a 标签
                self.crawl(url)

            if self._404_status != -1:  # valid web service
                # 网站主目录下扫描全部rule, 即rule和root_only标记的rule, 其他目录下扫描 只扫描rule
                rule_set_to_process = [self.rules_set, self.rules_set_root_only] if url == '/' else [self.rules_set]
                # 加载规则
                for rule_set in rule_set_to_process:
                    for _ in rule_set:
                        # _  ('/scripts/samples', 'IIS', 200, '', '', True, 'iis')
                        try:
                            full_url = url.rstrip('/') + _[0]
                        except Exception as e:
                            logger.log('ERROR', f'{str(e)}')
                            continue
                        if full_url in self.urls_enqueued:
                            continue
                        url_description = {'prefix': url.rstrip('/'), 'full_url': full_url}
                        item = (url_description, _[1], _[2], _[3], _[4], _[5], _[6])
                        self.url_list.append(item)
                        self.urls_enqueued.add(full_url)

            # 本来若只找到 /asdd/asd/ 这种链接，没有/asdd/ 这个子目录，会将/asdd/子目录添加进去处理
            if url.count('/') >= 2:
                self.enqueue('/'.join(url.split('/')[:-2]) + '/')  # sub folder enqueue

            if url != '/' and not self.no_scripts:
                for script in self.user_scripts:
                    self.url_list.append((script, url))

            return True
        except Exception as e:
            logger.log('ERROR', '[_enqueue.exception] %s' % str(e))
            return False

    # 在页面中匹配rules的白名单规则
    def find_text(self, html_doc):
        for _text in self.text_to_find:
            if html_doc.find(_text) >= 0:
                return True, 'Found [%s]' % _text
        for _regex in self.regex_to_find:
            if _regex.search(html_doc):
                return True, 'Found Regex [%s]' % _regex.pattern
        return False

    # 匹配黑名单规则
    def find_exclude_text(self, html_doc):
        for _text in self.text_to_exclude:
            if html_doc.find(_text) >= 0:
                return True
        for _regex in self.regex_to_exclude:
            if _regex.search(html_doc):
                return True
        return False

    # 循环爬取页面的超链接，放入队列self.enqueue()， 匹配rules的白名单规则
    def crawl(self, path, do_not_process_links=False):
        try:
            status, headers, html_doc = self.http_request(path)

            if path == '/':
                self.index_status, self.index_headers, self.index_html_doc = status, headers, html_doc
            if not do_not_process_links and html_doc:
                soup = BeautifulSoup(html_doc, "html.parser")
                # 循环爬取a标签
                for link in soup.find_all('a'):
                    url = link.get('href', '').strip()
                    if url.startswith('..'):
                        continue
                    if not url.startswith('/') and url.find('//') < 0:  # 相对路径
                        url = path + url
                    url, depth = cal_depth(self, url)

                    if depth <= self.max_depth:
                        self.enqueue(url)
                # 匹配rules的白名单规则
                ret = self.find_text(html_doc)
                if ret:
                    if '/' not in self.results:
                        self.results['/'] = []
                    m = re.search('<title>(.*?)</title>', html_doc)
                    title = m.group(1) if m else ''
                    _ = {'status': status, 'url': '%s%s' % (self.base_url, path), 'title': title, 'vul_type': ret[1]}
                    if _ not in self.results['/']:
                        self.results['/'].append(_)

        except Exception as e:
            logger.log('ERROR', '[crawl Exception] %s %s' % (path, str(e)))

    # 读取rules目录下的相关规则
    def _init_rules(self):
        self.text_to_find = []
        self.regex_to_find = []
        self.text_to_exclude = []
        self.regex_to_exclude = []
        self.rules_set = set()
        self.rules_set_root_only = set()

        p_tag = re.compile('{tag="(.*?)"}')
        p_status = re.compile(r'{status=(\d{3})}')
        p_content_type = re.compile('{type="(.*?)"}')
        p_content_type_no = re.compile('{type_no="(.*?)"}')

        _files = self.args.rule_files if self.args.rule_files else glob.glob('rules/*.txt')
        # 读取规则
        for rule_file in _files:
            with open(rule_file, 'r', encoding='utf-8') as infile:
                vul_type = os.path.basename(rule_file)[:-4]
                for url in infile.readlines():
                    url = url.strip()
                    if url.startswith('/'):
                        _ = p_tag.search(url)
                        tag = _.group(1) if _ else '' # 没有tag字段时，赋空

                        _ = p_status.search(url)
                        status = int(_.group(1)) if _ else 0

                        _ = p_content_type.search(url)
                        content_type = _.group(1) if _ else ''

                        _ = p_content_type_no.search(url)
                        content_type_no = _.group(1) if _ else ''

                        root_only = True if url.find('{root_only}') >= 0 else False
                        rule = (url.split()[0], tag, status, content_type, content_type_no, root_only, vul_type)

                        if root_only:
                            if rule not in self.rules_set_root_only:
                                self.rules_set_root_only.add(rule)
                            else:
                                logger.log('ERROR', f'Duplicated root only rule: {rule}')
                        else:
                            if rule not in self.rules_set:
                                self.rules_set.add(rule)
                            else:
                                logger.log('ERROR', f'Duplicated rule: {rule}')

        # 读取匹配黑/白名单
        re_text = re.compile('{text="(.*)"}')
        re_regex_text = re.compile('{regex_text="(.*)"}')
        file_path = 'rules/white.list'
        if not os.path.exists(file_path):
            logger.log('ERROR', f'File not exist: {file_path}')
            return
        for _line in open(file_path, 'r', encoding='utf-8'):
            _line = _line.strip()
            if not _line or _line.startswith('#'):
                continue
            _m = re_text.search(_line)
            if _m:
                self.text_to_find.append(_m.group(1))
            else:
                _m = re_regex_text.search(_line)
                if _m:
                    self.regex_to_find.append(re.compile(_m.group(1)))

        file_path = 'rules/black.list'
        if not os.path.exists(file_path):
            logger.log('ERROR', f'File not exist: {file_path}')
            return
        for _line in open(file_path, 'r', encoding='utf-8'):
            _line = _line.strip()
            if not _line or _line.startswith('#'):
                continue
            _m = re_text.search(_line)
            if _m:
                self.text_to_exclude.append(_m.group(1))
            else:
                _m = re_regex_text.search(_line)
                if _m:
                    self.regex_to_exclude.append(re.compile(_m.group(1)))

    # 读取script目录下的相关插件
    def _init_scripts(self):
        self.user_scripts = []
        if self.args.no_scripts:  # 全局禁用插件，无需导入
            return
        for _script in self.args.script_files:
            script_name_origin = os.path.basename(_script)
            script_name = script_name_origin.replace('.py', '')
            try:
                self.user_scripts.append(importlib.import_module('scripts.%s' % script_name))
            except Exception as e:
                logger.log('ERROR', 'Fail to load script %s' % script_name)

    def scan_worker(self, item):
        if not self.flag and time.time() - self.start_time > self.timeout:
            self.flag = True
            if self.flag:
                self.url_list.clear()
                logger.log('ALERT', '[ERROR] Timed out task: %s' % self.base_url)
            return
        url, url_description, tag, status_to_match, content_type, content_type_no, root_only, vul_type, prefix = None, None, None, None, None, None, None, None, None
        try:
            if len(item) == 2:  # Script Scan
                check_func = getattr(item[0], 'do_check')
                check_func(self, item[1])
            else:
                # ({'prefix': '', 'full_url': '/trace'}, 'Spring boot serverProperties', 200, '', '', True, 'springboot')
                url_description, tag, status_to_match, content_type, content_type_no, root_only, vul_type = item
                prefix = url_description['prefix']
                url = url_description['full_url']
                '''
                {sub} 这个是规则里设置的， 主要是根据当前域名来做字典，
                比如{sub}.sql ,当前域名为baidu.com ，则规则改为 baidu.sql
                '''
                if url.find('{sub}') >= 0:
                    if not self.domain_sub:
                        return
                    url = url.replace('{sub}', self.domain_sub)

        except Exception as e:
            logger.log('ERROR', '[scan_worker.1] %s' % str(e))
            logger.log('ERROR', traceback.format_exc())
            return
        if not item or not url:
            return

        # 开始规则目录探测
        try:
            status, headers, html_doc = self.http_request(url)
            cur_content_type = headers.get('content-type', '')
            cur_content_length = headers.get('content-length', len(html_doc))

            if self.find_exclude_text(html_doc):  # 黑名单规则排除
                return
            if 0 <= int(cur_content_length) <= 10:  # text too short
                return
            if cur_content_type.find('image/') >= 0:  # exclude image
                return

            # 当指定 content_type 时,
            if content_type and content_type != 'json' and cur_content_type.find('json') >= 0:
                return
            # content type mismatch
            if (content_type and cur_content_type.find(content_type) < 0) or (
                    content_type_no and cur_content_type.find(content_type_no) >= 0):
                return
            if tag and html_doc.find(tag) < 0:
                return  # tag mismatch

            # 在页面中匹配rules的白名单规则
            if self.find_text(html_doc):
                valid_item = True
            else:
                # status code check
                if status_to_match == 206 and status != 206:
                    return
                if status_to_match in (200, 206) and status in (200, 206):
                    valid_item = True
                elif status_to_match and status != status_to_match:
                    return
                elif status in (403, 404) and status != status_to_match:
                    return
                else:
                    valid_item = True

                if status == self._404_status and url != '/':
                    len_doc = len(html_doc)
                    len_sum = self.len_404_doc + len_doc
                    if len_sum == 0 or (0.4 <= float(len_doc) / len_sum <= 0.6):
                        return

            if valid_item:
                m = re.search('<title>(.*?)</title>', html_doc)
                title = m.group(1) if m else ''
                # self.print_msg('[+] [Prefix:%s] [%s] %s' % (prefix, status, 'http://' + self.host +  url))
                if prefix not in self.results:
                    self.results[prefix] = []
                _ = {'status': status, 'url': '%s%s' % (self.base_url, url), 'title': title, 'vul_type': vul_type}
                if _ not in self.results[prefix]:
                    self.results[prefix].append(_)
        except Exception as e:
            logger.log('ERROR', '[scan_worker.2][%s] %s' % (url, str(e)))
            traceback.print_exc()

    # 使用多线程对目标进行扫描
    def scan(self):
        try:
            start_time = time.time()
            loop = asyncio.get_event_loop()
            import platform
            if platform.system() != "Windows":
                import uvloop
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            p = ThreadPoolExecutor(5)

            tasks = [loop.run_in_executor(p, self.scan_worker, item) for item in self.url_list]
            # 这一步很重要，使用loop.run_in_executor()函数:内部接受的是阻塞的线程池，执行的函数，传入的参数
            # 即对网站访问10次，使用线程池访问

            try:
                loop.run_until_complete(asyncio.wait(tasks))
            except KeyboardInterrupt:
                # 当检测到键盘输入 ctrl c的时候
                all_tasks = asyncio.Task.all_tasks()
                # 获取注册到loop下的所有task
                for task in all_tasks:
                    task.cancel()
                    # 取消该协程,如果取消成功则返回True
                loop.stop()
                # 停止循环
                loop.run_forever()
                # loop事件循环一直运行
                # 这两步必须要做
            finally:
                loop.close()
                # 关闭事件循环

            logger.log('INFOR', f'{self.base_url} 规则探测使用 {time.time() - start_time:0.2f} s')

            # 等待所有的任务完成
            for key in self.results.keys():
                # todo 为何？
                # 超过5个网址在这个文件夹下发现，保留第一个
                if len(self.results[key]) > 5:
                    self.results[key] = self.results[key][:1]
            return self.base_url.lstrip('unknown://').rstrip(':None'), self.results
        except Exception as e:
            logger.log('ERROR', f'[scan exception] {str(e)}')