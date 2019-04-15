#!/usr/bin/python
# -*- coding: utf-8 -*-
import json
import string
import urlparse
from random import choice
from urllib import urlencode

from engine.engine_utils.common import *
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
        path = item['url']
        params = item['params']
        method = item['method']
        timeout = ob.get('webTimeout')
        pattern = r'(/j_security_check\?loginButton=Login)'
        p_para = r'("type":\s*"password")'
        result = []
        if not (re.search(pattern, path, re.I) or re.search(p_para, json.dumps(params), re.I)):
            pass
        elif re.search(r'(.js|.css)', path, re.I):
            pass
        elif params and 'POST' == method.upper():
            pattern1 = r'("type":"text"|"type":"password")'
            p1 = re.compile(pattern1)
            text_count = len(p1.findall(params))
            if text_count != 2:
                pass
            else:
                source_ip = ob.get('source_ip')
                url_parse = urlparse.urlparse(path)
                scheme = url_parse.scheme
                domain = url_parse.netloc
                path = url_parse.path
                query = url_parse.query

                if source_ip:
                    domain = source_ip
                if query:
                    new_url = "%s://%s%s?%s" % (scheme, domain, path, query)
                else:
                    new_url = "%s://%s%s" % (scheme, domain, path)
                username, password = param_get_username_pwd(json.loads(params))
                flag_list = ['Just refresh the page... login will take over', 'GlassFish Console - Common Tasks',
                 '/resource/common/js/adminjsf.js">', 'Admin Console</title>', 'src="/homePage.jsf"',
                 'src="/header.jsf"', 'src="/index.jsf"', '<title>Common Tasks</title>', 'title="Logout from GlassFish']
                username_list = ['administrator', 'test', 'Admin', 'manage', 'admin', 'root']
                password_list = ['administrator', 'abcd1234', '111111', '666666', '888888', '000000', '123456',
                                 '654321', '222222', '123123',
                                 '321321', '123321', '012345', 'abc123', '123abc', 'aaaaaa', 'abcdef', 'admin000',
                                 'admin', '123', '321', 'test', 'demo', '1234', '12345', 'manage', 'pass',
                                 '00000000', '11111111', '66666666', '88888888', '12345678', '87654321', '01234567',
                                 '76543210',
                                 '09876543', 'glassfish','1','root','1234567890','test1234','password','abcd1234', 'phplist']
                params_weekpass_list = inj_params2(username, password, un_value=username_list,
                                                   ps_value=password_list)
                for body in params_weekpass_list:
                    res, content = http.request(new_url, 'POST', body=body, headers=header)
                    if int(res.get('status', 0)) != 404:
                        for flag in flag_list:
                            if re.search(flag, content, re.I):
                                detail = "Glassfish弱口令:%s" % body
                                response = getResponse(res)
                                request = postRequest(new_url, 'POST', headers=header, body=body)
                                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                                break

        return result

    except Exception, e:
        logger.error("File:crack_glassfish_weak_pwd_url.py, run_url function :%s" % (str(e)))
        return result


def gen_password(count=4, length=8, chars=string.ascii_letters + string.digits):
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


def param_get_username_pwd(params_list):

    for param in params_list:
        if 'password' == param.get('type'):
            password = param.get('name')
        if 'text' == param.get('type'):
            username = param.get('name')

    return username, password


def inj_params(param_dict, inj_point, inj_value=None):
    param_list = []
    for value in inj_value:
        param_dict[inj_point] = value
        for key in param_dict.keys():
            if inj_point != key and param_dict[key] == "":
                param_dict[key] = 'admin'
        param_list.append(urlencode(param_dict))
    return param_list


def inj_params2(username, password, un_value=None, ps_value=None):
    param_list = []
    param_dict = {}
    for ps in ps_value:
        param_dict[password] = ps
        for un in un_value:
            param_dict[username] = un
            param_list.append(urlencode(param_dict))
    return param_list
