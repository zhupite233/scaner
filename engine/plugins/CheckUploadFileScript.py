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
        if item['params'] != '':
            return []
        #end if
        if item['url'][-1] != '/':
            return []
        #end if
        
        url = item['url']
        
        list = ['upload.html','upload.htm']
        if ob['siteType'] == 'php':
            list.append('upload.php')
        elif ob['siteType'] == 'asp':
            list.append('upload.asp')
        elif ob['siteType'] == 'aspx':
            list.append('upload.aspx')
        elif ob['siteType'] == 'jsp':
            list.append('upload.jsp')
        else:
            list.extend(['upload.php','upload.asp','upload.aspx','upload.jsp'])
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
        relist = ["%s%s" % (new_url,row) for row in list]
        relist = valid_urls(domain, relist)
        if not relist:
            return result

        detail = "在站点上检测到潜在的文件上传"
        for url in relist:
            res, content = http.request(new_url, headers=header)
            if res and res.has_key('status') and res['status'] == '200' and res.has_key('content-type') and res['content-type'] != '' and content != '' and content.find('input') >= 0 and content.find('file') >= 0 and content.find('type') >= 0:
                match = re.findall(r"<(\s*)input(\s+)type(\s*)=(\s*)('|\")file\5(.+?)>",content,re.I|re.DOTALL)
                if match and len(match) > 0:
                    request = getRequest(url, domain=ob['domain'])
                    output = "...<%sinput%stype%s=%s%sfile%s%s>..." % (match[0][0],match[0][1],match[0][2],match[0][3],match[0][4],match[0][4],match[0][5])
                    response = getResponse(res, output)
                    result.append(getRecord(ob,url,ob['level'],detail,request,response,output))
                #end if
            #end if
        #end for
        
        return result
    except Exception,e:
        logger.error("File:CheckUploadFileScript.py, run_url function :" + str(e))
        return []
    #end try    
#end def

