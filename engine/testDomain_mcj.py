# -*- coding: utf-8 -*-
import urlparse
from random import random
from time import time
from engine_lib.HttpRequest import HttpRequest


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


def make_ob(url=None, cookie=''):
    url_parse = urlparse.urlparse(url)
    config = {'cookie': cookie, 'siteId': '1111',
              'vulId': '',
              'ip': url_parse.netloc, 'isstart': 1,
              'webTimeout': 10,
              'scheme': url_parse.scheme,
              'domain': url_parse.netloc,
              'level': 'HIGH',
              'path': '/' if not url_parse.path else url_parse.path,
              'taskId': 976,
              'site_dirs': ['/www/news/']}
    config['404_page'], config['waf_page'] = get_invaild_page(url_parse.scheme, url_parse.netloc)

    config['404_page']['similar_rate'] = 0.8
    config['waf_page']['similar_rate'] = 0.8
    return config


def start_scan(script, url=None, cookie=None):
    ob = make_ob(url, cookie)
    # from engine.plugins.phpMyadminblackdoorScript import run_domain
    exec ("from plugins.%s import *" % script)

    http = HttpRequest({'timeout': ob['webTimeout'], 'cookie': ob['cookie']})
    result = run_domain(http, ob)
    print result
    return result


if __name__ == '__main__':
    script = 'manage_page'
    # script = 'CheckRobotsScript'
    url = 'http://option.luhongsuo.cn/'

    cookie = ''

    start_scan(script, url, cookie)
