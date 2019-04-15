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
        if item['params'] != '':
            return []
        #end if
        if item['url'][-1] != '/':
            return []
        #end if
        if ob['siteType'] in ['asp','aspx','jsp']:
            return []
        #end if
        source_ip = ob.get('source_ip')
        header = {'Host': ob['domain']}
        domain = source_ip if source_ip else ob['domain']
        url_parse = urlparse(item['url'])
        scheme = ob['scheme']
        path = url_parse.path
        query = url_parse.query
        if query:
            new_url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            new_url = "%s://%s%s" % (scheme, domain, path)
        url = "%sphpinfo.php" % (new_url)
        res, content = http.request(url, headers=header)
        if res and res.has_key('status') and res['status'] == '200' and res.has_key('content-type') \
                and res['content-type'] != '' and content.find('PHP Version') >= 0:
            detail = "在 Web 站点上安装了缺省样本脚本或目录"
            output = ""
            request = getRequest(url, domain=ob['domain'])
            response = getResponse(res, content, keywords='PHP Version')
            result.append(getRecord(ob,url,ob['level'],detail,request,response,output))
        #end if

        return result
    except Exception,e:
        logger.error("File:CheckPhpinfoScript.py, run_url function :" + str(e))
        return []
    #end try
#end def

