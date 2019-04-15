#!/usr/bin/python
# -*- coding: utf-8 -*-
import json
import string
from copy import deepcopy
from random import choice
from urllib import urlencode
import requests
from engine.engine_utils.common import *
from urlparse import urlparse
from engine.logger import scanLogger as logger


def run_url(http, ob, item):
    header = {
        "Host": ob['domain'],
        "Connection": "keep-alive",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "Referer": item['refer'],
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        # "Cookie": ob.get('cookie')
    }
    try:
        url = item['url']
        params = item['params']
        method = item['method']
        timeout = ob.get('webTimeout')
        pattern = r'(login|sigin)'
        p_para = r'("type":\s*"password")'
        result = []
        if not (re.search(pattern, url, re.I) or re.search(p_para, json.dumps(params), re.I)):
            pass
        elif re.search(r'(.js|.css)', url, re.I):
            pass
        else:
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
            if params and 'POST' == method.upper():
                # params_list = json.loads(params)
                inj_point, param_dict = param2dict(json.loads(params))
                if inj_point:

                    new_param_dict = deepcopy(param_dict)
                    time_list = []
                    for length in [20, 200, 600]:
                        pwd = gen_password(1, length)
                        new_param_dict[inj_point] = pwd[0]
                        r = requests.post(new_url, new_param_dict)
                        time_list.append(r.elapsed.microseconds)
                    if time_list[0]+50000 < time_list[1] and time_list[1]+50000 < time_list[2]:
                        response = getResponse(r.headers)
                        request = getRequest(new_url, domain=ob['domain'])
                        detail = "存在使用超长密码登录攻击风险"
                        result.append(getRecord(ob, new_url, ob['level'], detail, request, response))

        return result

    except Exception, e:
        logger.error("File:check_login_long_pwd_url.py, run_url function :%s" % (str(e)))
        return result


def gen_password(count=4, length=8, chars=string.ascii_letters+string.digits):
    '''
    python3中为string.ascii_letters,而python2下则可以使用string.letters和string.ascii_letters
    :param count: the count of passwords
    :param length:
    :param chars:
    :return: pwd list
    '''
    pwd_list = []
    for i in range(count):
        # 密码的长度为8
        pwd = ''.join([choice(chars) for i in range(length)])
        pwd_list.append(pwd)
    return pwd_list


def param2dict(params_list):
    param_dict = {}
    for param in params_list:
        if 'password' == param.get('type'):
             inj_point = param.get('name')

        if 'submit' != param.get('type'):
             param_dict[param['name']] = param['value']

    return inj_point, param_dict


def inj_params(param_dict, inj_point, inj_value=None):

    param_list = []
    for value in inj_value:
        param_dict[inj_point] = value
        for key in param_dict.keys():
            if inj_point != key and param_dict[key]=="":
                param_dict[key] = 'admin'
        param_list.append(urlencode(param_dict))
    return param_list

def inj_params2(param_dict, inj_point, un_value=None, ps_value=None):

    param_list = []
    for ps in ps_value:
        param_dict[inj_point] = ps
        for un in un_value:
            for key in param_dict.keys():
                if inj_point != key and param_dict[key]=="":
                    param_dict[key] = un
            param_list.append(urlencode(param_dict))
    return param_list