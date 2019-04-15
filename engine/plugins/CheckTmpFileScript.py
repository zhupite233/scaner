#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from urlparse import urlparse

from engine.logger import scanLogger as logger

def run_url(http,ob,item):
    try:
        result = []
        if item['method'] != 'get':
            return []
        #end if
        url = item['url']
        if url.find('.php') < 0 and url.find('.asp') < 0 and url.find('.aspx') < 0 and url.find('.jsp') < 0 and url.find('.do') < 0:
            return []
        #end if
        header = {'Host': ob['domain']}
        url_parse = urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query
        if query:
            new_url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            new_url = "%s://%s%s" % (scheme, domain, path)
        domain = ob['domain']
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        detail = "Web 服务器通常没有这些文件扩展名的特定处理程序。 如果攻击者请求这类文件，文件内容会直接发送到浏览器。"
        list = ['.bak','.sav','.old','~']
        relist = ["%s%s" % (new_url,row) for row in list]
        relist = valid_urls(domain, relist)
        if not relist:
            return result
        for new_url in relist:
            #new_url = "%s%s" % (url,row)
            res, content = http.request(new_url, headers=header)
            if res and res.has_key('status') and res['status'] == '200' and res.has_key('content-type') and res['content-type'] != '' and content.find("<%") >= 0:
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res)
                result.append(getRecord(ob,new_url,ob['level'],detail,request,response))
            #end if
        #end for
        
        if len(result) >= 2:
            return []
        else:
            return result
        #end if

    except Exception,e:
        logger.error("File:CheckTmpFileScript.py, run_url function :" + str(e))
        return []
    #end try    
#end def

