#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http, ob):
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        result = []
        header = {

            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": ob.get('cookie') if ob.get('cookie') else '',
            "Host": domain
        }
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s" % (scheme, domain)
        res, content = http.request(new_url, 'GET', headers=header)
        if res.get('status') == '200':
            server = res.get('server')
            if server in ['nginx/1.3.9', 'nginx/1.4.0']:
                response = getResponse(res)
                request = getRequest(new_url, domain=ob['domain'])
                detail = "nginx版本%s过低，存在Nginx缓冲区溢出漏洞" % server
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                return result
    except Exception, e:
        logger.error("File:NginxBufferUnderflowScript_yd.py, run_domain function :%s" % (str(e)))
        return []
