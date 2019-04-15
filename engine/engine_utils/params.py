# --*-- coding: utf-8 --*--
import json
from urllib import urlencode
from urlparse import parse_qs,urlparse


def query2dict(params):
    '''
    将get请求的query转换成字典 a=1&b=2 ==> {'a':'1','b':'2'}
    :param params: 数据库中spider_url表的params字段
    :return:
    '''
    dict1 = parse_qs(params, True)
    dict2 = {}
    for k, v in dict1.iteritems():
        dict2[k] = v[0]
    return dict2


def dict2query(params_dict, isUrlEncode=True):
    '''
    字典转换为query字符串，只针对一维字典  {'a':'1','b':'2'} ==> a=1&b=2
    输入参数：
        {"a":"b"}
        {"a":"b","c":"d"}
    输出数据：
        a=b
        a=b&c=d
    '''
    if isUrlEncode:
        return urlencode(params_dict)
    else:
        kv_list = []
        for k in params_dict.keys():
            kv_list.append(k + "=" + params_dict[k])
        return "&".join(kv_list)

def db_params2dict(params):
    '''
    将post请求的params转换成字典
    [{"type":"submit","name":"seclev_submit","value":"Submit"},{"type":"select","name":"security","value":"low"}]
    ==>
    {"security":"low"}
    :param params: post请求，数据库中spider_url表的params字段，字典构成的列表
    :return: 转换后的params，字典
    '''
    #  (改成不去掉submit 20170803)
    try:
        body_list = json.loads(params)
        body_dict = {}
        for body in body_list:
            # if body["type"] != "submit":
            body_dict[body["name"]] = body["value"]
        return body_dict
    except Exception, e:
        return {}

def post_query2dict(url):
    '''
    将post请求的query转换成字典
    http://www.sohu.com?w_keyword=
    ==>
    {"w_keyword":""}
    :param url: 数据库中spider_url表的url字段
    :return: 转换后的query，字典
    '''
    query_str = urlparse(url).query
    query_dict = query2dict(query_str)
    return query_dict

def post_all_query2dict(url):
    '''
    将post请求的query转换成字典
    http://www.sohu.com?w_keyword=
    ==>
    {"w_keyword":""}
    :param url: 数据库中spider_url表的url字段
    :return: 转换后的query，字典
    '''
    #http://www.lsu.edu.cn/_web/search/doSearch.do?_p=YXM9NCZ0PTUmZD04NCZwPTEmbT1TTiY_
    parseResult = urlparse(url)
    urlBase = "%s://%s%s" % (parseResult.scheme, parseResult.netloc, parseResult.path)
    queryDict = query2dict(parseResult.query)
    return urlBase, queryDict

def post_params2str(params):
    '''
    莫诚就预留函数
    将post请求的params（数据库中spider_url表的params字段）, 转换成字符串 a=1&b=2的形式
    数据库中，post请求的params是json格式，是由字典构成的列表
    :param params:  post请求，数据库中spider_url表的params字段
    :return: 转换成字符串的params a=1&b=2
    '''
    params_list = json.loads(params)
    params_dict = {}
    for param in params_list:
        if 'submit' != param.get('type'):
             params_dict[param['name']] = param['value']
    params_str = urlencode(params_dict)
    return params_str
