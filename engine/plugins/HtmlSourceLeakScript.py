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
        if url.find('.html') < 0 and url.find('.htm') < 0 and url.find('.php') < 0 and url.find('.asp') < 0 and url.find('.aspx') < 0 and url.find('.jsp') < 0 and url.find('.do') < 0:
            return []
        #end if
        
        params = item['params']
        if params != "":
            url = "%s?%s" % (url,params)
        #end if
        detail = "发现HTML的注释信息，可能包含程序员的调试信息或者存在遗留的重要敏感信息。"
        res, content = http.request(url, 'GET', headers=header)
        request = getRequest(url, domain=ob['domain'])
        response = getResponse(res)
        if res and res.has_key('status') and res['status'] == '200' and content.find("<!--") >= 0 and content.find("-->") >= 0:
            match = re.findall(r"<!--(\s*)(.+?)(\s*)-->",content,re.I|re.DOTALL)
            if match and len(match) > 0:
                for row in match:
                    key = row[1]
                    if key != "":
                        m = re.findall(r"(\s+)(admin|username|password|passwd)(\s+)",key,re.I)
                        if m and len(m) > 0:
                            result.append(getRecord(ob,url,ob['level'],detail,request,response))
                            break
                        #end if

                        m = re.findall(r"(.+?)\.(asp|php|jsp|aspx|do|pl|txt|rar|zip|tar)",key,re.I)
                        if m and len(m) > 0:
                            result.append(getRecord(ob,url,ob['level'],detail,request,response))
                            break
                        #end if
                        
                        m = re.findall(r"(\s+)(http|https|ftp):\/\/",key,re.I)
                        if m and len(m) > 0:
                            result.append(getRecord(ob,url,ob['level'],detail,request,response))
                            break
                        #end if
                        
                        m = re.findall(r"(function|<%)",key,re.I)
                        if m and len(m) > 0:
                            result.append(getRecord(ob,url,ob['level'],detail,request,response))
                            break
                        #end if

                        m = re.findall(r"(\s+)([cdefgh]:\\)",key,re.I)
                        if m and len(m) > 0:
                            result.append(getRecord(ob,url,ob['level'],detail,request,response))
                            break
                        #end if
                    #end if
                #end for
            #end if
        #end if
        
        return result
    except Exception,e:
        logger.error("File:HtmlSourceLeakScript.py, run_url function :" + str(e))
        return []
    #end try    
#end def

