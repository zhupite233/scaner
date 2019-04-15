# --*-- coding: utf-8 --*--
import json
import os
from urlparse import urlparse, urlsplit, parse_qs

import httplib2

from config import SPIDER_TOKEN
from config import SPIDER_URL


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


def get_url_element(url=None, params='', method='get'):

    # url = 'http://military.cnr.cn/gz/20170709/8shiuige'
    # params = 'newsid=523255577&status=1&time=1499656178734'
    # method = 'get'
    url_ext = os.path.splitext(urlsplit(url).path)[-1][1:]
    url_path = urlsplit(url).path
    if url_ext:
        url_file = url_path.split('/')[-1]
        url_dir = url_path.rstrip(url_file)
    else:
        url_dir = url_path
    if params:
        params_dict = query2dict(params)
        params_keys_set = set(params_dict.keys())
    else:
        params_keys_set = set()
    return url_dir, url_ext, params_keys_set


def get_url_data(execute_id):
    url = '%s/execute/urlsbyid/%s' % (SPIDER_URL, execute_id)
    header = {'token': SPIDER_TOKEN,'Content-Type': 'application/x-www-form-urlencoded'}
    ignore_ext = ['js', 'css', 'png', 'jpg', 'gif', 'bmp', 'svg', 'exif', 'jpeg', 'exe', 'rar', 'zip']
    http = httplib2.Http()
    for _i in xrange(3):
        try:
            res, content = http.request(url, 'GET', headers=header)
            con = json.loads(content)
            if res.get('status') == '200' and con.get('status') == 'ok':
                data_list = con.get('data')
                break
        except Exception, e:
            data_list = None
            continue
    domain_dirs = set()
    if data_list:
        try:

            url_elements_list = []
            for data in data_list:

                url = data.get('url')
                # url_parse = urlparse.urlparse(url)
                url_ext = os.path.splitext(urlsplit(url).path)[-1][1:]
                if url_ext in ignore_ext:
                    continue
                method = data.get('method')
                post = data.get('post')
                query = data.get('query')
                params = post
                if 'GET'==method:
                    url = url.split('?')[0]
                    params = query
                    # 针对get的url去重（因为post的参数类型暂时不支持去重)
                    url_elements = (url_dir, url_ext, params_keys) = get_url_element(url, params, method)
                    if url_dir:
                        domain_dirs.add(url_dir)
                    if url_elements in url_elements_list:
                        continue
                    else:
                        url_elements_list.append(url_elements)
                # http_code = data.get('http_code')
                refer = data.get('referer')
                url_domain = urlparse(url).netloc
                url_domain = url_domain.split(':')[0]
        except Exception,e:
            print e

if __name__ == '__main__':


    # url_elements = (url_dir, url_ext, params_keys) = get_url_element()
    # print url_elements
    get_url_data(6396)
