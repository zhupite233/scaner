#!/usr/bin/python
# -*- coding: utf-8 -*-
import urlparse

from engine.engine_utils.common import *
from engine.engine_utils.rule_result_judge import page_similar
from engine.logger import scanLogger as logger


def LinkInjectionCheck(http,ob,url, header):
    try:
        result = []
        if url == "":
            return result
        #end if
        expurl = "%s%s" % (url,"<iframe%20src=http://www.baidu.com></iframe>")
        res, content = http.request(expurl, 'GET', headers=header)
        if res['status'] == '404' or len(content) <= 0:
            return result
        if page_similar(res.get('status'), content, ob.get('404_page')):
            return result
        if page_similar(res.get('status'), content, ob.get('waf_page')):
            return result
        #end if
        flag, keyword = LinkGetKeyWord(content,"src=http://www.baidu.com></iframe>")
        if flag:
            detail = u"该URL可能会导致链接注入。测试链接为："
            detail = "%s%s%s" % (detail.encode('utf-8'),url,keyword)
            request = getRequest("%s%s" % (url,keyword), domain=ob['domain'])
            response = getResponse(res)
                
            result.append(getRecord(ob,url,ob['level'],detail,request,response)) 
        #end if
        return result
    except Exception,e:
        logger.error("File:LinkInjectionScript.py, LinkInjectionCheck function :" + str(e))
        return []
    #end try       
#end def
    

def run_url(http,ob,item):
    try:
        list = []
        if item['method'] != 'get' or item['params'] == '':
            return list

        if checkUrlType(item['url']) == False:
            return list
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        params = changeParams(item['params'])
        url = item['url']
        url_parse = urlparse.urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query

        if source_ip:
            domain = source_ip
        if query:
            new_url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            new_url = "%s://%s%s" % (scheme, domain, path)
        for row in params:

            url = "%s?%s" % (new_url,row)
            res = LinkInjectionCheck(http,ob,url, header)
            if len(res) > 0:
                list.extend(res)
            #end if
        #end for
        
        return list
    except Exception,e:
        logger.error("File:LinkInjectionScript.py, run_url function :" + str(e))
        return []
    #ene  try
#end def


