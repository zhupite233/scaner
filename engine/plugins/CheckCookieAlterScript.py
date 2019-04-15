#!/usr/bin/python
# -*- coding: utf-8 -*-

from engine.engine_utils.common import *
from urlparse import urlparse
from engine.logger import scanLogger as logger


def run_url(http, ob, item):
    try:
        result = []
        if item['method'] != 'get':
            return []
        header = {"Host": ob['domain']}
        url = item['url']
        url_parse = urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        if query:
            new_url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            new_url = "%s://%s%s" % (scheme, domain, path)
        params = item['params']
        if params != "":
            url = "%s?%s" % (new_url, params)
        else:
            url = new_url
        res, content = http.request(url, 'GET', headers=header)
        if res and res.has_key('status') and res['status'] == '200' and res.has_key('content-type') and res[
            'content-type'] != '' and content.find("document.cookie") >= 0:
            list = content.replace("\r\n", "\n").split("\n")
            for row in list:
                if row.find("document.cookie") < 0:
                    continue
                # end if
                match = re.findall(r"document.cookie(\s*)=", row, re.I)
                if match and len(match) > 0:
                    detail = "Cookie 是在客户端创建的。代码用于操纵站点的 cookie。可以将实施 cookie 逻辑的功能移至客户端（浏览器）。这样一来，攻击者就能发送其本无权发送的 cookie。"
                    request = getRequest(url, domain=ob['domain'])
                    response = getResponse(res, row, keywords="document.cookie(\s*)=")
                    result.append(getRecord(ob, url, ob['level'], detail, request, response, ""))
                    break
                    # end if
                    # end for
        # end if

        return result
    except Exception, e:
        logger.error("File:CheckCookieAlterScript.py, run_url function :" + str(e))
        return []
        # end try

# end def
