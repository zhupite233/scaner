#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.inj_functions import header_inject
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from urlparse import urlparse
from engine.engine_utils.rule_result_judge import page_similar


def run_url(http, ob, item):
    inj_list = [
        '/test<script>alert(133)</script>',
        '\'-<script>alert(133)</script>',
        '\"-<script>alert(133)</script>',
        '%27-<script>alert(133)</script>',
        '%2527-<script>alert(133)</script>',
        '%22-<script>alert(133)</script>',
        '%2522-<script>alert(133)</script>'
    ]
    result = []
    domain = ob['domain']
    scheme = ob['scheme']
    header = {'Host': domain}
    source_ip = ob.get('source_ip')
    if source_ip:
        domain = source_ip
    url = item['url']
    url_parse = urlparse(url)
    path = url_parse.path
    query = url_parse.query
    try:
        result = []
        header = {
            "Host": ob['domain'],
            "Referer": '%s://%s/' % (scheme, ob['domain']),
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": ob.get('cookie') if ob.get('cookie') else '',
        }
        for inj_value in inj_list:
            new_url = "%s://%s%s?%s%s" % (scheme, domain, path, query, inj_value)
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.has_key('status') and res['status'] == '200':
                if page_similar(res.get('status'), content, ob.get('404_page')):
                    continue
                keyword = re.search(r'<script>alert(133)</script>', content)
                if keyword:
                    response = getResponse(res, content)
                    request = getRequest(new_url, domain=ob['domain'])
                    detail = "存在url注入的XSS漏洞"
                    result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
    except Exception, e:
        logger.error("File:xss_script_domain.py, run_domain function :%s" % (str(e)))
    return result