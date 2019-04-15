#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
import re


def run_domain(http, ob):
    '''
    CNNVD-201108-440
    CVE-2011-3192
    Apache HTTP Server畸形Range选项处理远程拒绝服务漏洞

    CVSS分值:	7.8	[严重(HIGH)]
    CWE-399	[资源管理错误]
    '''
    result = []
    try:
        server = ob.get('webServer')
        if server in ['nginx', 'iis']:
            return []

        scheme = ob['scheme']
        domain = ob['domain']
        header = {
            "User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding":"gzip, deflate",
            "Range":"",
            "Connection":"close",
            "Host": domain
        }

        inj_range = "bytes=1-1,1-2,1-3,1-4,1-5,1-6"
        header['Range'] = inj_range
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s" % (scheme, domain)
        res, content = http.request(new_url, 'HEAD', headers=header)
        if res and res.get('status') == 206:  # 206表示服务器成功处理了分片请求，如果是200则不能证明存在该漏洞
            detail = '检测到Apache Httpd 远程拒绝服务漏洞, http_code=206表示服务器成功处理了分片请求'
            request = getRequest(new_url, headers=header, domain=ob['domain'])
            response = getResponse(res)
            result.append(getRecord(ob, new_url, ob['level'], detail, request, response=response))

    except Exception, e:
        logger.error("File:ApacheHttpdRemoteDenialService_yd.py, run_domain function :%s" % (str(e)))

    return result

