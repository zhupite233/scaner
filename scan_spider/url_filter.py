# --*-- coding: utf-8 --*--
import json
import os
import re
from urlparse import urlsplit, parse_qs


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


def get_url_element(url=None, params='', method='get', post_data=None):

    # url = 'http://military.cnr.cn/gz/20170709/8shiuige'
    # params = 'newsid=523255577&status=1&time=1499656178734'
    # method = 'get'
    url_split = urlsplit(url)
    url_ext = os.path.splitext(url_split.path)[-1][1:]
    url_path = url_split.path
    url_query = url_split.query
    url_file = url_path.split('/')[-1]
    if url_ext:
        url_dir = url_path.rstrip(url_file)
    else:
        m = re.search('.+\/\.(.+)', url_path)
        if m:
            url_ext = m.groups()[0]
            url_dir = url_path.rstrip(url_file)
        else:
            url_dir = url_path
    if not url_dir:
        url_dir = '/'
    if '#' == url_dir[-1]:
        url_dir = url_dir.rstrip('#')
    params_keys_list = []
    if 'POST' == method.upper() and post_data:
        params_keys_list.extend(post_data.keys())
        params = url_query

    if params:
        if re.search(r'=+.*&*', params, re.I):
            params_dict = query2dict(params)
        else:
            params_dict = json.loads(params)
        params_keys_list.extend(params_dict.keys())

    params_keys_set = set(params_keys_list)
    return url_dir, method, url_ext, params_keys_set

