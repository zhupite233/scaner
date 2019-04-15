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
            "Host": domain,
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
            "Cookie": ob.get('cookie') if ob.get('cookie') else ''
            # "Connection": "keep-alive"
        }

        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = "%s://%s/manager/html" % (scheme, domain)
        res, content = http.request(new_url, 'GET', headers=header)

        if res.get('status') == '401' or res.get('status') == '200' and re.search(r'Apache Tomcat', content, re.I):
            response = getResponse(res, content, 'Apache Tomcat')
            request = getRequest(new_url, domain=ob['domain'])
            detail = "tomcat管理后台开放至外网，存在安全风险"
            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
        url_list = ['/examples/jsp/snp/snoop.jsp.html', '/examples/jsp/snp/snoop.jsp', '/jsp-examples/snp/snoop.jsp']
        for url in url_list:
            new_url = "%s://%s%s" % (scheme, domain, url)
            res, content = http.request(new_url, 'GET', headers=header)
            if res.get('status') == '200' and re.search(r'Request Information', content, re.I):
                response = getResponse(res, content, 'Request Information')
                request = getRequest(new_url, domain=ob['domain'])
                detail = "访问到Tomcat示例Web应用程序，存在安全风险"
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                break
        return result
    except Exception, e:
        logger.error("File:ScanWeakPwdForTomcatScript_yd.py, run_domain function :%s" % (str(e)))
        return result
