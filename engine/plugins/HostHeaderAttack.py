#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import urllib
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

_xforwardedhost = None
def run_url(http,ob,item):
    result = []
    try:
        detail = u""
        url = urllib.unquote(item['url'])
        host = "evilXForwardedHost.com"
        header = {"Cookie":ob.get('cookie') if ob.get('cookie') else '',"X-Forwarded-Host": host,"Connection":"Keep-alive","User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.1) Gecko/20090624 Firefox/3.5"}
        # res, content = requestUrl(http,url)
        res, content = http.request(url, 'GET', body='', headers=header)
        if res and content.find(host) != -1:
            request = getRequest(url,headers=header, domain=ob['domain'])
            response = getResponse(res, content, host)
            result.append(getRecord(ob,item['url'],ob['level'],detail,request,response))
        #end if
    except Exception,e:
        logger.error("File:HostHeaderAttack.py, run_url function :%s" % (str(e)))
    #end try
    return result
#end def
