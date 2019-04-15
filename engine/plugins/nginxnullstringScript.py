#!/usr/bin/env python
# -*- coding: utf-8 -*-
import urlparse

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_url(http,ob,item):
    list = []
    try:
        server = ob.get('webServer')
        if server and server not in ['nginx', 'iis']:
            return []
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        url = item['url']
        url_parse = urlparse.urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query

        if source_ip:
            domain = source_ip
        if query:
            url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            url = "%s://%s%s" % (scheme, domain, path)
        expurl="%s%s"%(url,"%20")
        res1, content1 = http.request(url, 'GET', headers=header)
        res2, content2 = http.request(url, 'GET', headers=header)
        if content1 == content2:
            return []
        if content2.find("<?php") >= 0 and content2.find("?>") >= 0:
            request = getRequest(expurl, domain=ob['domain'])
            response = getResponse(res2, content2)
            detail = "验证性扫描结果：\n%s" % content2
            list.append(getRecord(ob,expurl,ob['level'],detail,request,response))

    except Exception,e:
        logger.error("File:nginxnullstringscript.py, run_domain function :" + str(e))
    #end try
    
    return list
#end def 
