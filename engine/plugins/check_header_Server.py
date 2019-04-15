#!/usr/bin/python
# -*- coding: utf-8 -*-

import re

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    try:
        # waf_page = ob.get('waf_page')
        # if waf_page:
        #     waf_code = waf_page.get('status')
        #     waf_content = waf_page.get('content')
        #     if waf_code == '461' and re.search('error461\.yundun\.com', waf_content):
        #         return []
        scheme = ob.get('scheme')
        domain = ob.get('domain')
        result_list = []
        new_header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s/" % (scheme,domain)
        res, content = http.request(new_url, "HEAD", headers=new_header)
        server = res.get('server')
        if server and not re.match('^WAF/[\d\.\-]{1,10}$', server, re.I):
            detail = "响应头检测到Server字段，可能泄露敏感信息: %s" % server
            request = getRequest(new_url, new_header, domain=ob['domain'])
            response = getResponse(res)
            result_list.append(getRecord(ob, new_url, ob['level'], detail, request, response, output=""))
        return result_list
    except Exception,e:
        logger.error("File:check_header_Server.py, run_domain function :%s" % (str(e)))
        return []


if __name__ == '__main__':
    from httplib2 import Http
    http = Http.request()
    ob = {}
    ob['domain'] = 'www.saas.sh.cn'
    ob['source_ip'] = None
    print run_domain(http, ob)
