#!/usr/bin/python
# -*- coding: utf-8 -*-

import urlparse

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_url(http,ob,item):
    try:
        webserver = ob.get('webServer')
        if webserver and webserver in ['apache', 'nginx']:
            return []
        result = []
        if item['method'] != 'get':
            return []
        domain = ob['domain']
        headers = {'Host': domain, 'Cookie': "ASPSESSIONIDCSCDSCSS=LDMJENIAIBHHKKGHOKAPHFPB", 'Accept': "*/*",
                   'Accept-Language': "en-US", 'User-Agent': "Mozilla/4.0 (compatible; MSIE 6.0; Win32)",
                   'Referer': "http://%s/" % (ob['domain']), 'Translate': "f",
                   'Content-Type': "application/x-www-form-urlencoded"}
        url = item['url']
        if url.find('.asp') < 0 and url.find('.aspx') < 0:
            return []
        url_parse = urlparse.urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        if query:
            url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            url = "%s://%s%s" % (scheme, domain, path)
        res, content = http.request(url, 'GET', body = '', headers = headers)
        if res['status'] == '200':
            match = re.findall(r"<%(.+?)%>",content,re.I|re.DOTALL)
            if match and len(match) > 1:
                headers2 = {}
                headers2['Cookie'] = "ASPSESSIONIDCSCDSCSS=LDMJENIAIBHHKKGHOKAPHFPB"
                headers2['Accept'] = "*/*"
                headers2['Accept-Language'] = "en-US"
                headers2['User-Agent'] = "Mozilla/4.0 (compatible; MSIE 6.0; Win32)"
                headers2['Host'] = ob['domain']
                headers2['Referer'] = "http://%s/" % (ob['domain'])
                headers2['Translate'] = "f"
                headers2['Content-Type'] = "application/x-www-form-urlencoded"
                request = getRequest(url,"GET",headers2,"", domain=ob['domain'])
                response = getResponse(res,"")
                detail = u"该网站的IIS服务器开启了脚本资源访问，将导致网站的源码泄露，建议管理员进入IIS管理器关闭脚本资源访问功能。"
                detail = detail.encode('utf8')
                
                result.append(getRecord(ob,url,ob['level'],detail,request,response))
            #end if
        #end if
        
        return result
    except Exception,e:
        logger.error("File:IISResourceAccessScript.py, run_url function :" + str(e))
        return []
    #end try    
#end def
