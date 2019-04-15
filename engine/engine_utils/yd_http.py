# -*-encoding:UTF-8-*-
'''
本库仅用于处理HTTP请求，是扫描项目基础的公用库
'''

import re
import sys
import ssl
import copy
import types
import httplib
import httplib2
import urlparse

def request(url='', method="GET", body='', headers={}, redirections=5, timeout=30):
    '''
    本函数已经过讨论
    请求参数
        url，请求的URL
        method，请求的方式，GET/POST/PUT/DELETE等
        body，请求体
        headers，请求头，字典类型
        redirections，跳转跟踪尝试
        timeout，超时时间设置
    返回结果
        请求URL，此项处理是基于httplib2，返回的信息包括：
        httpcode，正常请求，返回正常的httpCode，请求超时或异常时，状态码为0，错误信息写入error字段
        request_headers，请求头，字典类型
        request_body，请求内容
        response_headers，响应头，字典类型
        response_body，响应内容
        error，请求不成功时的错误信息
    '''
    returnDict = {'url':url, 'method':method, 'httpcode':0, 'request_headers':headers, 'request_body':body, 'response_headers':{}, 'response_body':'', 'error':''}
    if not url:
        returnDict['error'] = 'url is empty'
        return returnDict

    #将请求方式转换为大写
    method = method.upper()

    try:
        #设置超时时间
        http = httplib2.Http(timeout=timeout, disable_ssl_certificate_validation = True)
        #发起请求
        response_headers, response_body = http.request(url, method, body=body, headers=headers, redirections=redirections)
        #捕获httpcode
        returnDict['httpcode'] = response_headers.status
        #捕获响应头
        returnDict['response_headers'] = response_headers
        #捕获响应内容
        returnDict['response_body'] = response_body
    except Exception, e:
        returnDict['error'] = e.message
    return returnDict

