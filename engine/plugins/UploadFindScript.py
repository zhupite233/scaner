#!/usr/bin/python
# -*- coding: utf-8 -*-

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from urlparse import urlparse


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
        url_parse = urlparse(url)
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

        if url.lower().find(".js")>=0 and url.lower().find(".jsp")<0:
            return []
        if item['params'] != '':
            url = "%s?%s" % (url,item['params'])
        #end if
        if checkUrlType(item['url']) == False or item['url'][-1] == '/':
            return []
        #end if
        res, content = http.request(url, 'GET', headers=header)
        if res.has_key('status') and res['status'] != '200':
            return []
        #end if
        
        if len(content) <= 0:
            return []
        #end if
        match = re.findall(r"<(\s*)form(\s+)(.+?)>(.+?)<(\s*)/(\s*)form(\s*)>",content,re.I|re.DOTALL)
        if match and len(match) > 0:
            for row in match:
                value = row[2].lower()
                if value.find("enctype") < 0 or value.find("multipart/form-data") < 0:
                    continue
                #end if
                match2 = re.findall(r"type=(\"|')file\1",row[3],re.I)
                if match2 and len(match2) > 0:
                    detail = u"该URL中包含上传点，可能会包含上传漏洞并且被黑客利用。"
                    detail = detail.encode('utf-8')
                    request = getRequest(url, domain=ob['domain'])
                    response = getResponse(res, content)

                    result.append(getRecord(ob,url,ob['level'],detail,request,response))

        return result
    
    except Exception,e:
        logger.error("File:UploadFindScript.py, run_url function :" + str(e))
        return []


