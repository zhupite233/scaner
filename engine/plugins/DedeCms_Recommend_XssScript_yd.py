#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    result = []
    try:

        frame = ob.get('siteType')
        if frame and frame in ['asp', 'aspx', 'jsp']:
            return []

        scheme = ob['scheme']
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        result = []

        inj_path_list = [
            "/plus/recommend.php?aid=1&action=sendmail&title=%3Ciframe%20src=//scan.yundun.com/static/js/yundun_test.txt%3E%3C/iframe%3E",

            "/dede/plus/recommend.php?aid=1&action=sendmail&title=%3Ciframe%20src=//scan.yundun.com/static/js/yundun_test.txt%3E%3C/iframe%3E"
        ]

        for inj_path in inj_path_list:
            new_url = "%s://%s%s" % (scheme, domain, inj_path)
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.get('status') == '200' and re.search(r'YunDun_ScANtEST', content):
                detail = '检测到织梦CMS\'recommend.php\'XSS漏洞'
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res,content)
                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:DedeCms_RecommendXssScript_yd.py, run_domain function :%s" % (str(e)))

    return result