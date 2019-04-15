#!/usr/bin/python
# -*- coding: utf-8 -*-
import urllib
from cStringIO import StringIO
from engine.engine_lib import yd_json as json
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
import urlparse
#header inject
_headerKey = "NvsInjHeader"
_headerValue = "nvsinjected"
_headerKeyWord = "\n%s:%s" %(_headerKey,_headerValue)

#redirect inject
_redirKeyWord = "Header may not contain more than a single header, new line detected"


def _encode_multipart(data,row,injectType):
    """
    injectType: {1:header,2:redir}
    """
    boundary = '--------------NvscanBoundaryLWYILYHBY1314520'
    sep_boundary = '\r\n--' + boundary
    end_boundary = sep_boundary + '--'
    body = StringIO()
    for key, value in data.items():
        # handle multiple entries for the same name
        if type(value) != type([]):
            value = [value]
        for value in value:
            if type(value) is tuple:
                fn = '; filename="%s"' % value[0]
                value = value[1]
            else:
                fn = ""

            body.write(sep_boundary)
            body.write('\r\nContent-Disposition: form-data; name="%s"' % key)
            body.write(fn)
            body.write("\r\n\r\n")
            if key == row:
                if injectType == 1:
                    body.write("\r\n%s:%s" %(_headerKey,_headerValue))
            else:
                body.write(value)
    body.write(end_boundary)
    body.write("\r\n")
    return body.getvalue(), boundary

def headerInject(res,content):
    if content.find(_redirKeyWord) != -1:
        return True
    for value in res.itervalues():
        if value.find(_headerKeyWord) != -1:
            return True
    #end for
    return False


def run_url(http,ob,item):
    result = []
    try:
        if item['params'] == '':
            return result
        #end if
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        url = urllib.unquote(item['url'])
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
        _http=http
    
        if item['method'] == 'get':
            params_dict = dict(map(lambda s: s.split('=',1) if len(s.split('='))>1 else [s[:s.find('=')],''],item['params'].split('&')))
            for row in params_dict:
                tmp = params_dict.copy()
                tmp[row] = '%%0d%%0a%s%%3a%s' %(_headerKey,_headerValue)
                new_url = "%s?%s" %(url, '&'.join("%s=%s" %(k,v) for k,v in tmp.iteritems()))
                res, content = http.request(url, 'GET', headers=header)
                if (res.has_key(_headerKey) and res[_headerKey] == _headerValue) or headerInject(res,content):
                    request = getRequest(new_url, domain=ob['domain'])
                    response = getResponse(res)
                    detail = "注入参数："+row
                    result.append(getRecord(ob,new_url,ob['level'],detail,request,response))
                #end if
            #end for

        elif item['method'] == 'post':
            params_list = json.read(item['params'])
            params = {}
            upload = False
            for row in params_list:
                if row['type'] == 'file':
                    upload = True
                    params[row['name']] = ('','')
                else:
                    params[row['name']] = row['value']
            #end for
            if upload:
                for row in params:
                    data, boundary = _encode_multipart(params,row,1)
                    headers = {'Content-Type': 'multipart/form-data; boundary=%s' % boundary,
                            'Content-Length': str(len(data)),
                        }
                    res,content = _http.request(url, 'POST', data, headers=headers)
                    if (res.has_key(_headerKey) and res[_headerKey] == _headerValue) or headerInject(res,content):
                        request = postRequest(url,data=data, domain=ob['domain'])
                        response = getResponse(res)
                        detail = "注入参数："+row
                        result.append(getRecord(ob,url,ob['level'],detail,request,response))
                    #end if
                #end for
            else:
                for row in params:
                    headers = {"Content-Type":"application/x-www-form-urlencoded"}                
                    tmp = params.copy()
                    tmp[row] = '\r\n%s:%s' %(_headerKey,_headerValue)
                    data = urllib.urlencode(tmp)
                    res,content = _http.request(url, 'POST', data, headers=headers)
                    if (res.has_key(_headerKey) and res[_headerKey] == _headerValue) or headerInject(res,content):
                        request = postRequest(url,data=data, domain=ob['domain'])
                        response = getResponse(res)
                        detail = "注入参数："+row
                        result.append(getRecord(ob,url,ob['level'],detail,request,response))
                    #end if
                #end for
            #end if
        #end if
        return result

    except Exception,e:
        logger.error("File:HttpResponseSplit.py, run_url function :%s" % (str(e)))
    #end try
    return result
#end def
