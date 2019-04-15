#!/usr/bin/env python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

def run_domain(http,ob):
    list = []
    try:
        detail = u'cookie没有设置Secure属性'
        detail = detail.encode('utf8')
        scheme = ob.get('scheme')
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        if 'https'!= scheme :
            return list
        url = "%s://%s%s" % (ob['scheme'],domain,ob['path'])
        res, content = http.request(url, 'GET', headers=header)
        if res['status'] == '200' and res.has_key('set-cookie') and res['set-cookie'].lower().find('secure') < 0:
            request = getRequest(url, domain=ob['domain'])
            response = getResponse(res)
            list.append(getRecord(ob,url,ob['level'],detail,request,response))
    except Exception,e:
        logger.error("File:CookieWithoutSecureScript.py, run_domain function :" + str(e))
    #end try

    return list
#end def

