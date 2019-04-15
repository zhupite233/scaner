# -*- coding: utf-8 -*-
import sys
from random import random
from time import time

import httplib2
import urlparse
import json
# import MySQLdb
# import MySQLdb.cursors
from engine_lib.HttpRequest import HttpRequest
from engineConfig import *


# def get_spider_url(url_id=None):
#     # 从数据库中查询单条URL进行扫描
#     sql = "select * from spider_url where id=%d" % url_id
#     db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass = MySQLdb.cursors.DictCursor)
#     cursor = db.cursor()
#     cursor.execute(sql)
#     row = cursor.fetchone()
#     db.close()
#     return row
def get_invaild_page(scheme, domain, source_ip=None):
    current_time = time()
    random_num = random()
    new_domain = source_ip if source_ip else domain
    path_404 = ('/%f%f' % (current_time, random_num)).replace('.', '/')
    url_404 = "%s://%s%s.abc" % (scheme, new_domain, path_404)  # 用当前时间戳和随机数构成不存在的url，后缀.abc
    header = {'Host': domain}
    # --- update by mochj after testing the rule_scan
    http = HttpRequest({'timeout': 30, 'follow_redirects': True})
    try:
        res_404, content_404 = http.request(url_404, redirections=5, headers=header)
        status_404 = int(res_404.get('status', 0))
    except:
        status_404 = 0
        content_404 = None
    path_waf = '/test?a=1%27%20or%201=1'
    url_waf = "%s://%s%s" % (scheme, new_domain, path_waf)  # 构造一个非法url，如果有waf就会被拦截
    try:
        res_waf, content_waf = http.request(url_waf, redirections=5, headers=header)
        status_waf = int(res_waf.get('status', 0))
    except:
        status_waf = 0
        content_waf = None
    if status_waf == status_404 and content_waf == content_404:
        status_waf = None  # status_waf = None 代表waf拦截页面就是404页面，后面插件不需要做waf页面判断
        content_waf = None
    dict_404 = {'status': status_404, 'content': content_404}
    dict_waf = {'status': status_waf, 'content': content_waf}
    return dict_404, dict_waf

def make_ob_and_item(url_id=None, url=None, params=None, method='GET', cookie=None, source_ip=None):

    item = make_item_manual(url, params, method)
    scan_url = url if url else item.get('url')
    url_parse = urlparse.urlparse(scan_url)
    config = {'cookie': cookie,
              'siteId': item.get('site_id') if item.get('site_id') else '1111',
              'vulId': '',
              'ip': '192.168.3.51',
              'isstart': 1,
              'webTimeout': 30,
              'scheme': url_parse.scheme,
              'domain': url_parse.netloc,
              'level': 'HIGH',
              'path': url_parse.path,
              'taskId': 505,
              'source_ip': source_ip
              }
    config['404_page'], config['waf_page'] = get_invaild_page(url_parse.scheme, url_parse.netloc)

    config['404_page']['similar_rate'] = 0.8
    config['waf_page']['similar_rate'] = 0.8
    return config, item


def make_item_manual(url=None, params=None, method='get'):
    # 组织数据
    item = {"url": url,
            "params": params,
            "method": method,
            "refer": url
            }
    return item


def start_scan(script, url_id=None, url=None, params=None, method='GET', cookie=None, source_ip=None):
    '''
    :param script:
    :param url_id:
    :return:
    '''

    ob, item = make_ob_and_item(url_id, url, params, method, cookie, source_ip)
    exec("from plugins.%s import *" % script)

    cookie = ob['cookie'] if ob['cookie'] else ''
    http = HttpRequest({'timeout': ob['webTimeout'], 'follow_redirects':True,'cookie': cookie})
    result = run_url(http, ob, item)
    print result
    return result

if __name__ == '__main__':
    url_id = None
    script = 'exec_cmd_dns_log'
    url = None if url_id else 'http://192.168.3.86:8092/login'
    method = None if url_id else 'get'

    cookie = ""
    source_ip = None
    params = None if url_id else 'id=1&name=jjj'
    res = start_scan(script, url_id, url, params, method, cookie, source_ip)
    print res
