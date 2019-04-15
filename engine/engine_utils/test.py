# --*--coding:utf-8--*--

import re
from urllib import urlencode
from copy import deepcopy
from urlparse import parse_qs

def make_new_body(body_dict,inj_point_list,inj_value_list,inj_way="append"):
    new_body_list = []
    #增加参数
    if inj_way == "add":
        for inj_point in inj_point_list:
            for inj_value in inj_value_list:
                body_str = urlencode(body_dict)
                new_body_str = "%s&%s=%s" % (body_str,inj_point,inj_value)
                new_body_list.append(new_body_str)
        return new_body_list

    body_dict_bak = deepcopy(body_dict)
    if inj_way == "replace":
        for inj_point in inj_point_list:
            for inj_value in inj_value_list:
                body_dict_bak[inj_point] = inj_value
                new_body_str = urlencode(body_dict_bak)
                new_body_list.append(new_body_str)
                body_dict_bak[inj_point] = body_dict[inj_point] # 恢复初始值
    else:
        for inj_point in inj_point_list:
            for inj_value in inj_value_list:
                body_dict_bak[inj_point] += inj_value
                new_body_str = urlencode(body_dict_bak)
                new_body_list.append(new_body_str)
                body_dict_bak[inj_point] = body_dict[inj_point] # 恢复初始值

    return new_body_list

def body_inject2(body_list,inj_point,inj_value_list,inj_way="append"):
    # 把body从字典组成的列表转换成纯字典，去掉submit元素
    body_dict = {}
    for body in body_list:
        if body.get("type") != "submit":
            body_dict[body["name"]] = body["value"]
    # 识别哪些参数需要注入，需要注入的加入到inj_point_list
    inj_point_list = []
    if inj_point == "inj_all" or inj_point == "":
        for k,v in body_dict.iteritems():
            inj_point_list.append(k)
    else:
        for k,v in body_dict.iteritems():
            if re.search(inj_point,k,re.I) or re.search(inj_point,v,re.I):
                inj_point_list.append(k)
    # 调inject_body函数，返回字符串构成的body列表
    if body_dict and inj_point_list:
        new_body_list = make_new_body(body_dict,inj_point_list,inj_value_list,inj_way)
        return new_body_list


print body_inject2([{"name":"a","value":"1"},{"name":"b","value":"2"},{"name":"aaa","type":"submit"}],"a",['xxx','yyy'],"append")