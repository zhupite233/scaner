#!/usr/bin/python
# -*- coding: utf-8 -*-
# 引入插件公用方法（必须）
from engine.engine_utils.common import *
# 导入日志对象
from engine.logger import scanLogger as logger


def run_domain(http, ob):
    '''
    引擎调用插件有两种方式，这是其中一种run_domain，所以函数名不能修改
    :param http: 引擎传入的http对象
    :param ob: 引擎传入的参数，字典类型，常用key如：
    {'domain': 'demo.aisec.cn', 'cookie': None, 'path': '/demo/', 'source_ip': '182.48.105.212', 'scheme': 'http'}
    :return:
    '''
    result = []
    try:
        server = ob.get('webServer')
        if server in ['nginx', 'iis']:
            return []

        scheme = ob['scheme']
        domain = ob['domain']
        cookie = ob.get('cookie')
        result = []

        inj_value = 't' * 4097  # cookie长度超过4K 字节才会触发漏洞
        if cookie:
            new_cookie = cookie + ';' + inj_value
        else:
            new_cookie = inj_value
        # 新构造头部，一般主需要构造注入项和Host，其中Host用于绕过waf扫描
        new_header = {'Cookie': new_cookie, 'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        # 构造注入的URL
        new_url = "%s://%s/" % (scheme, domain)
        # 发起http请求，request函数原型： def request(self, url, method="GET", body=None, headers=None, redirections=5,
        # connection_type=None):
        res, content = http.request(url=new_url, method='GET', headers=new_header)
        # 判断漏洞存在条件
        if res and res.get('status') == '200' and re.search(r'cookie\s*?:.*?tttt', content, re.I):
            # 以下为结果回传及结果写入数据库
            detail = "检测到Apache cookie 泄露漏洞"
            request = getRequest(new_url, headers=new_header, domain=ob['domain'])
            response = getResponse(res, content, keywords='t{40}')
            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:ApacheCookieDisclose_yd.py, run_domain function :%s" % (str(e)))

    return result
