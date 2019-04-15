#!/usr/bin/env python
# -*- coding: utf-8 -*-
import urlparse

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar


def run_url(http,ob,item):
    detail=""
    detail=detail.encode('utf8')
    list=[]
    domain = ob['domain']
    header = {'Host': domain}
    source_ip = ob.get('source_ip')
    try:
        url=item['url']
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
        if url.find(".gif")<0 and url.find(".jpg")<0:
            return list
        explist=['/c.php','%00.php']       
        for exp in explist:
            expurl="%s%s"%(url,exp)
            response, content = http.request(url, 'GET', headers=header)
            if response['status']=='200' and response['content-type']=='text/html':
                if page_similar(response.get('status'), content, ob.get('404_page')):
                    continue
                if page_similar(response.get('status'), content, ob.get('waf_page')):
                    continue
                else:
                    request = getRequest(expurl, domain=ob['domain'])
                    response = getResponse(response)
                    list.append(getRecord(ob,expurl,ob['level'],detail,request,response))
                    break
        return list

    except Exception,e:
        logger.error("File:NginxParsingVulnerabilities.py, run_url function :" + str(e))
        return list

