#!/usr/bin/python
# -*- coding: utf-8 -*-
from urllib import urlencode
from copy import deepcopy
from json import dumps
import re
import urllib2
from urlparse import urlparse,urlunparse,urljoin,parse_qs

#构造注入头部

# v1.0 函数，仅支持单个注入值
def header_inject1(header,inj_point,inj_value,inj_way):
    new_header = deepcopy(header)
    if inj_way == "append": #在原有的值后面追加注入内容
        if new_header.has_key(inj_point):
            new_header[inj_point] += inj_value
    elif inj_way == "replace": #用注入内容替换原有值，如果没有该参数，则直接添加
        new_header[inj_point] = inj_value
    #因为是字典，暂时做不到add模式，也就是构造两个相同的header参数，比如 'Host':'www.baidu.com','Host':'www.sina.com'
    return new_header

def header_list_inject1(header,inj_point_list,inj_value,inj_way):
    new_header_list = []
    new_header = deepcopy(header)
    if inj_way == "append": #在原有的值后面追加注入内容
        for inj_point in inj_point_list:
            if new_header.has_key(inj_point):
                new_header[inj_point] += inj_value
                new_header_list.append(new_header)
                new_header[inj_point] = header[inj_point] # 恢复初始值，不影响下个参数
    elif inj_way == "replace":
        # 用注入内容替换原有值，如果没有该参数，则直接添加
        for inj_point in inj_point_list:
            new_header[inj_point] = inj_value
            new_header_list.append(new_header)
            new_header[inj_point] = header[inj_point] # 恢复初始值，不影响下个参数
    #因为是字典，暂时做不到add模式，也就是构造两个相同的header参数，比如 'Host':'www.baidu.com','Host':'www.sina.com'
    return new_header_list


# v1.0 每次传入一个inj_value, 返回new_path
def path_inject1(path,inj_value,inj_way="append"):
    if path:
        # 替换模式
        if inj_way == "replace":
            if inj_value[0] == "/":
                new_path = inj_value
            else:
                new_path = "/" + inj_value
        # append、add模式都是追加，其他非法输入也按append模式
        else:
            # 注入值以/开头
            if inj_value[0] == "/":
                # 路径以/结尾，去掉重复的/
                if path[-1] == "/":
                    new_path = path[0:-1] + inj_value
                # 路径以非/结尾
                else:
                    p = path.split("/")
                    # 最后一段中包含点，去掉最后带点的部分。例如 /test/index.php  去掉index.php
                    if re.search("\.",p[-1]):
                        n = len(p[-1]) # 通过字符串长度实现，出于性能考虑
                        path_1 = path[0:-(n+1)]   # 删除最后一段路径以及最后一个/
                        new_path = path_1 + inj_value
                    # 最后一段路径中不包含点
                    else:
                        new_path = path + inj_value
            # 注入值非/开头
            else:
                # 路径以/结尾
                if path[-1] == "/":
                    new_path = path + inj_value
                # 路径以非/结尾
                else:
                    p = path.split("/")
                    # 最后一段中包含点，去掉最后带点的部分。例如 /test/index.php  去掉index.php
                    if re.search("\.",p[-1]):
                        n = len(p[-1])
                        path_1 = path[0:-n]
                        new_path = path_1 + inj_value
                    else:
                        new_path = path + "/" + inj_value
    # path 为空
    else:
        if inj_value[0] == "/":
            new_path = inj_value
        else:
            new_path = "/" + inj_value
    return new_path


# query参数注入
def make_new_query1(query_dict, inj_point_list, inj_value, inj_way="append"):
    # inj_point_list的元素是要注入的每个参数名，
    new_query_list = []
    query_dict_bak = deepcopy(query_dict)
    for inj_point in inj_point_list:
        # 替换初始值
        if inj_way == "replace":
            query_dict_bak[inj_point] = inj_value
        # 在初始值后面追加
        elif inj_way == "append":
            query_dict_bak[inj_point] += inj_value
        else: # 其他非法输入按append模式
            query_dict_bak[inj_point] += inj_value
        new_query = urlencode(query_dict_bak) #生成urlencode之后的query字符串
        new_query_list.append(new_query)
        query_dict_bak[inj_point] = query_dict[inj_point] #恢复初始值，不影响下一个参数
    return new_query_list  #列表的元素是字符串 a=1&b=2&c=3

# query注入，一般是get请求，部分post请求也有query
def query_inject1(query_str,inj_point,inj_value,inj_way="append"):
    new_query_list = []
    if inj_way == "add": #增加参数
        new_query = "%s&%s=%s" % (query_str,inj_point,inj_value)
        new_query_list.append(new_query)
        return new_query_list
    else:
        query_dict = parse_qs(query_str,True)
        query_dict_bak = {}
        inj_point_list = []
        for k,v in query_dict.iteritems():
            # value是一个列表，取列表第一个元素
            query_dict_bak[k] = v[0]
            #所有参数依次注入
            if inj_point == "inj_all" or inj_point == "":
                inj_point_list.append(k)
            elif re.search(inj_point,k,re.I) or re.search(inj_point,v,re.I):  #只注入指定的参数
                inj_point_list.append(k)
        if inj_point_list:
            new_query_list = make_new_query1(query_dict_bak,inj_point_list,inj_value,inj_way)
        return new_query_list

#body参数注入 表单参数 一般是post请求
def make_new_body1(body_dict,inj_point_list,inj_value,inj_way="append"):
    new_body_list = []
    for inj_point in inj_point_list:
        #增加参数
        if inj_way == "add":
            body_str = urlencode(body_dict)
            new_body_str = "%s&%s=%s" % (body_str,inj_point,inj_value)
            new_body_list.append(new_body_str)
        else:
            body_dict_bak = deepcopy(body_dict)
            if inj_way == "replace":
                body_dict_bak[inj_point] = inj_value
            elif inj_way == "append":
                body_dict_bak[inj_point] += inj_value
            else: # 其他非法输入也按apeend方式处理
                body_dict_bak[inj_point] += inj_value
            new_body_str = urlencode(body_dict_bak)
            new_body_list.append(new_body_str)

    return new_body_list


def body_inject1(body_json,inj_point,inj_value,inj_way="append"):
    # 把body从字典组成的列表转换成纯字典，去掉submit元素   (改成不去掉submit 20170803)
    body_dict = {}
    for body in body_json:
        # if body["type"] != "submit":
        body_dict[body["name"]] = body["value"]
    # 识别哪些参数需要注入，需要注入的加入到inj_point_list
    inj_point_list = []
    if inj_point == "inj_all" or inj_point == "":
        for k,v in body_dict.iteritems():
            if re.search(inj_point,k,re.I) or re.search(inj_point,v,re.I):
                inj_point_list.append(k)
    # 调inject_body函数，返回字符串构成的body列表
    if body_dict and inj_point_list:
        new_body_list = make_new_body1(body_dict,inj_point_list,inj_value,inj_way)
        return new_body_list


# =======================================================================

# v2.0 函数 支持注入值传入列表
def header_inject(header, inj_point_list, inj_value_list, inj_way="append"):
    '''
    头部注入函数，供外部调用
    :param header: 旧的头部，字典
    :param inj_point_list:  注入点，列表
    :param inj_value_list:  注入值，列表, 空元素会被移除
    :param inj_way:  注入方式，默认append
    :return:  新的头部，列表，元素是字典
    '''
    new_header_list = []
    while '' in inj_value_list:
        inj_value_list.remove('')
    new_header = deepcopy(header)
    if inj_way == "append":  # 在原有的值后面追加注入内容
        for inj_param in inj_point_list:
            if new_header.has_key(inj_param):
                for inj_value in inj_value_list:
                    new_header[inj_param] += inj_value
                    inj_header = deepcopy(new_header)
                    new_header_list.append(inj_header)
                    new_header[inj_param] = header[inj_param]  # 恢复初始值，不影响下个参数
    elif inj_way == "replace":
        # 用注入内容替换原有值，如果没有该参数，则直接添加
        for inj_param in inj_point_list:
            for inj_value in inj_value_list:
                new_header[inj_param] = inj_value
                inj_header = deepcopy(new_header)
                new_header_list.append(inj_header)
                new_header[inj_param] = header[inj_param]  # 恢复初始值，不影响下个参数
    elif inj_way == "add":
        # 增加一个header参数，如果原header已有这个参数，会被覆盖，实际结果等同于replace
        # 因为是字典，add模式暂时做不到构造两个相同的header参数，比如 'Host':'www.baidu.com','Host':'www.sina.com'
        for inj_param in inj_point_list:
            for inj_value in inj_value_list:
                new_header[inj_param] = inj_value
                inj_header = deepcopy(new_header)
                new_header_list.append(inj_header)
                del new_header[inj_param]
    return new_header_list


def path_inject(old_path, inj_value_list, inj_way="append"):
    '''
    路径注入函数，供外部调用
    :param old_path:  旧的路径，从新建任务的扫描路径传入  如 /test/aaa; 不接受 http://host_scan:port/test/aaa
    :param inj_value_list:  注入值，列表，空元素会被移除
    :param inj_way:  注入方式，默认append # 现在不论注入方式，replace和append的结果全部返回
    :return:  新的路径，列表
    '''
    # old_path是添加任务时输入的扫描路径
    new_path_list = []

    # 无论注入方式是什么，都会返回replace和append的new_path_list
    while '' in inj_value_list:
        inj_value_list.remove('')
    for inj_value in inj_value_list:
        if inj_value[0] != "/":
            inj_value = "/" + inj_value
        new_path = inj_value
        new_path_list.append(new_path)
    if not old_path:
        return new_path_list
    # old_path不为空，且以/结尾，去掉结尾的/
    if old_path[-1] == "/":
        old_path = old_path[0:-1]
    # old_path不为空，结尾不是/，以/为分割符，最后一段包含点的，例如/test/a.php，去掉最后一段和最后的/
    else:
        p = old_path.split("/")
        if re.search("\.", p[-1]):
            n = len(p[-1])
            old_path = old_path[0:-(n+1)]
    # 拼接old_path 和 inj_value，加到列表
    for inj_value in inj_value_list:
        if inj_value[0] != "/":
            inj_value = "/" + inj_value
        new_path = old_path + inj_value
        new_path_list.append(new_path)

    return new_path_list

# 构造query 内部调用
def make_new_query(query_dict, inj_point_list, inj_value_list, inj_way="append"):
    '''
    构造query，仅供query_inject内部调用
    :param query_dict: query，字典
    :param inj_point_list:  注入点，列表， 空值或者空白符会被视作默认值inj_all
    :param inj_value_list:  注入值，列表，空元素会被移除
    :param inj_way:  注入方式 默认append
    :return: 新的query，列表
    '''
    # inj_point_list的元素是要注入的每个参数名，
    new_query_list = []
    query_dict_bak = deepcopy(query_dict)
    # 替换初始值
    if inj_way == "replace":
        for inj_point in inj_point_list:
            for inj_value in inj_value_list:
                query_dict_bak[inj_point] = inj_value
                new_query = urlencode(query_dict_bak)  # 生成urlencode之后的query字符串
                new_query_list.append(new_query)
                query_dict_bak[inj_point] = query_dict[inj_point]  # 恢复初始值，不影响下一个参数
    # 在初始值后面追加
    else:  # append add 和其他非法输入都按append模式注入
        for inj_point in inj_point_list:
            for inj_value in inj_value_list:
                query_dict_bak[inj_point] += inj_value
                new_query = urlencode(query_dict_bak)
                new_query_list.append(new_query)
                query_dict_bak[inj_point] = query_dict[inj_point]
    return new_query_list  #列表的元素是字符串 a=1&b=2&c=3


def query_inject(query_str, inj_point, inj_value_list, inj_way="append"):
    '''
    query注入函数，供外部调用
    :param query_str:  爬虫爬到的url的query，字符串
    :param inj_point:  注入点，字符串，支持正则，空值或者空白符会被视作默认值inj_all
    :param inj_value_list:  注入值，列表，空元素会被移除
    :param inj_way:  注入方式 append/replace/add,默认append
    :return: 新的query，列表
    '''
    new_query_list = []
    while '' in inj_value_list:
        inj_value_list.remove('')
    if inj_way == "add":  # 增加参数
        for inj_value in inj_value_list:
            new_query = "%s&%s=%s" % (query_str, inj_point, inj_value)
            new_query_list.append(new_query)
        return new_query_list
    else:
        query_dict = parse_qs(query_str, True)
        query_dict_bak = {}
        inj_point_list = []
        for k, v in query_dict.iteritems():
            # value是一个列表，取列表第一个元素
            query_dict_bak[k] = v[0]
            #所有参数依次注入
            if not inj_point or inj_point == "inj_all" or re.match('^\s+$', inj_point):
                inj_point_list.append(k)
            elif re.search(inj_point, k, re.I) or re.search(inj_point, v, re.I):  # 只注入指定的参数
                inj_point_list.append(k)
        if inj_point_list:
            new_query_list = make_new_query(query_dict_bak, inj_point_list, inj_value_list, inj_way)
        return new_query_list


def make_new_body(body_dict, inj_point_list, inj_value_list, inj_way="append"):
    '''
    构造body的内部函数，仅供body_inject内部调用
    :param body_dict:  old body，字典
    :param inj_point_list: 注入点，列表  空值或者空白符会被视作默认值inj_all
    :param inj_value_list: 注入值，列表  空元素会被移除
    :param inj_way: 注入方式 append/replace/add
    :return: 构造后的body，列表
    '''
    new_body_list = []
    #增加参数
    if inj_way == "add":
        for inj_point in inj_point_list:
            for inj_value in inj_value_list:
                body_str = urlencode(body_dict)
                new_body_str = "%s&%s=%s" % (body_str, inj_point, inj_value)
                new_body_list.append(new_body_str)
        return new_body_list

    body_dict_bak = deepcopy(body_dict)
    if inj_way == "replace":
        for inj_point in inj_point_list:
            for inj_value in inj_value_list:
                body_dict_bak[inj_point] = inj_value
                new_body_str = urlencode(body_dict_bak)
                new_body_list.append(new_body_str)
                body_dict_bak[inj_point] = body_dict[inj_point]  # 恢复初始值
    else:
        for inj_point in inj_point_list:
            for inj_value in inj_value_list:
                body_dict_bak[inj_point] += inj_value
                new_body_str = urlencode(body_dict_bak)
                new_body_list.append(new_body_str)
                body_dict_bak[inj_point] = body_dict[inj_point]  # 恢复初始值

    return new_body_list


def body_inject(body_list,inj_point,inj_value_list,inj_way="append"):
    '''
    body注入函数，供外部调用
    :param body_list: body列表，元素是字典 [{"name":"a","value":"1"},{"name":"b","value":"2"}]
    :param inj_point: 注入点，字符串，允许正则，空值或者空白符会被视作默认值inj_all
    :param inj_value_list: 注入值，列表，空元素会被移除
    :param inj_way: append/replace/add
    :return: 新的body列表
    '''
    # 把body从字典组成的列表转换成纯字典，去掉submit元素  (改成不去掉submit 20170803)
    body_dict = {}
    while '' in inj_value_list:
        inj_value_list.remove('')
    for body in body_list:
        # if body["type"] != "submit":
        body_dict[body["name"]] = body["value"]
    # 识别哪些参数需要注入，需要注入的加入到inj_point_list
    inj_point_list = []
    if not inj_point or inj_point == "inj_all" or re.match('^\s+$', inj_point):
        for k, v in body_dict.iteritems():
            inj_point_list.append(k)
    else:
        for k, v in body_dict.iteritems():
            if re.search(inj_point, k, re.I) or re.search(inj_point, v, re.I):
                inj_point_list.append(k)
    # 调inject_body函数，返回字符串构成的body列表
    if body_dict and inj_point_list:
        new_body_list = make_new_body(body_dict, inj_point_list, inj_value_list, inj_way)
        return new_body_list


