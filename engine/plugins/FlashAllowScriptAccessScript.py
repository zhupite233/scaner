#!/usr/bin/python
# -*- coding: utf-8 -*-

import urlparse

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_url(http,ob,item):
    try:
        result = []
        if item['method'] != 'get':
            return []
        #end if
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
        params = item['params']
        if params != "":
            url = "%s?%s" % (url,params)
        #end if
        res, content = requestUrl(http,url)
        if res and res.has_key('status') and res['status'] == '200' and content.find('param') > 0 and (content.find('allowScriptAccess') > 0 or content.find('AllowScriptAccess') > 0):
            match = re.findall(r"<(\s*)param(\s+)name(\s*)=(\s*)('|\")allowscriptaccess\5(\s+)value(\s*)=(\s*)('|\")always\9(\s*)/(\s*)>",content,re.I|re.DOTALL)
            if match and len(match) > 0:
                detail = "Flash 显示程序接受 AllowScriptAccess 之类的对象参数。当父 SWF 装入子 SWF，并确定被装入的 SWF 与进行装入的 SWF 是否对 Web 页面脚本有相同的访问权时，会使用 AllowScriptAccess 参数。如果参数设为“always”，父项从任何域中装入的 SWF 都可能将脚本注入托管 Web 页面中。"
                request = getRequest(url, domain=ob['domain'])
                output = "<param name=%sallowscriptaccess%s value=%salways%s />" % (match[0][4],match[0][4],match[0][8],match[0][8])
                response = getResponse(res, output)
                result.append(getRecord(ob,url,ob['level'],detail,request,response,output))
            #end if
        #end if
        
        return result
    except Exception,e:
        logger.error("File:FlashAllowScriptAccessScript.py, run_url function :" + str(e))
        return []
    #end try    
#end def

