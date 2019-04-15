#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

def run_domain(http,ob):
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        path = ob['path']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        url = "%s://%s%s" % (scheme, domain, path)
        res, content = http.request(url, "OPTIONS", headers=header)
        
        list = []
        detail = u"该域名支持TRACE请求类型"
        detail = detail.encode("utf8")
        
        if res and res.has_key('status') and res['status'] == '200' and res.has_key('allow') and res['allow'].lower().find("trace") >= 0:
            request = getRequest(url,"OPTIONS", domain=ob['domain'])
            response = getResponse(res)
            list.append(getRecord(ob,url,ob['level'],detail,request,response))

        else:
            traceurl = url + '<script>alert(333)</script>'
            res, content = http.request(traceurl,'TRACE')
            if res and res.has_key('status') and res['status'] == '200' and content.lower().find('alert(333)') >=0:
                request = getRequest(traceurl,"TRACE", domain=ob['domain'])
                response = getResponse(res)
                list.append(getRecord(ob,url,ob['level'],detail,request,response))

        return list
    except Exception,e:
        logger.error("File:TraceHttpScript.py, run_domain function :%s" % (str(e)))  

    return []




