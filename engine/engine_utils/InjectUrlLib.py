#!/usr/bin/env python
# -*-encoding:UTF-8-*-
import copy
import random
import re
import types
import urllib
import urlparse

import httplib2

from engine.engine_utils.common import getRequest, getResponse
from params import dict2query


def getUrlsByQuerydictBodydictPayloads(url, queryDict={}, bodyDict={}, payloads=[], theKey='', injectWay="append"):
    '''
    获取要发起请求的URL 列表，每个URL包括两项元素，即URL和body
    本函数针对使用payload构造URL使用，可一次性批量获取要构造的URL
    本函数，GET/POST方式通用
    本函数可指定根据某个Key构造，也可全部构造
    :param url  基础的URL，不带query
    :param queryDict query，字典类型
    :param bodyDict 请求的body, 字典类型,在外部直接处理即可
    :param payloads 需要构造的payloads
    :param theKey 需要更改的key，为空则全部构造
    :param injectWay 注入方式，只有两种 replace,append
    :return 列表，列表元素为：{"url":"", "body":""}
    '''
    urls = []
    if not payloads:
        row = {}
        row['url'] = "%s?%s" % (url, dict2query(queryDict))
        row['body'] = dict2query(bodyDict)
        urls.append(row)
        return urls
        
    if queryDict:
        queryDicts = []
        if theKey:
            if queryDict.has_key(theKey):
                tmpList = getQuerydictByPayload(queryDict, theKey, payloads, injectWay)
                queryDicts.extend(tmpList)
        else:
            for key in queryDict.keys():
                tmpList = getQuerydictByPayload(queryDict, key, payloads, injectWay)
                queryDicts.extend(tmpList)
        for rowDict in queryDicts:
            row = {}
            row['url'] = "%s?%s" % (url, dict2query(rowDict))
            row['body'] = dict2query(bodyDict)
            urls.append(row)

    if bodyDict:
        bodyDicts = []
        currentUrl = "%s?%s" % (url, dict2query(queryDict))
        if theKey:
            if bodyDict.has_key(theKey):
                tmpList = getQuerydictByPayload(bodyDict, theKey, payloads, injectWay)
                bodyDicts.extend(tmpList)
        else:
            for key in bodyDict.keys():
                tmpList = getQuerydictByPayload(bodyDict, key, payloads, injectWay)
                bodyDicts.extend(tmpList)
        for rowDict in bodyDicts:
            row = {}
            row['url'] = currentUrl
            row['body'] = dict2query(rowDict)
            urls.append(row)
    return urls

def getQuerydictByPayload(queryDict = {}, theKey = "", payloads = [], inject_way="append"):
    '''
    使用payload获取要注入的参数字典
    输入参数：
        queryDict，请求的参数，字典类型
        theKey，进行注入的参数名称
        payloads，进行注入的payload列表
        inject_way，注入方式，有两种：replace替换原值 append在原值后追加数据
    输出参数：
        请求参数字典
    '''
    queryList = []
    if payloads:
        for payload in payloads:
            tmpDict = {}
            tmpDict = copy.deepcopy(queryDict)
            value = ""
            if inject_way == "append":
                value = tmpDict[theKey] + payload
            else: #inject_way == "replace"
                value = payload
            tmpDict[theKey] = value
            queryList.append(tmpDict)
    else:
        tmpDict = copy.deepcopy(queryDict)
        queryList.append(tmpDict)
    return queryList

def getHeaderdictByPayload(headerDict = {}, theKey = "", payloads = []):
    '''
    使用payload获取要注入的参数字典
    输入参数：
        headerDict，请求的header，字典类型
        theKey，进行注入的header
        payloads，进行注入的payload列表
    输出参数：
        请求参数字典
    '''
    headerList = []
    if payloads:
        for payload in payloads:
            tmpDict = {}
            tmpDict = copy.deepcopy(headerDict)
            value = tmpDict[theKey] + payload
            tmpDict[theKey] = value
            headerList.append(tmpDict)
    else:
        tmpDict = copy.deepcopy(headerDict)
        headerList.append(tmpDict)
    return headerList

def getUrlByQuerydict(url = "", queryDict={}):
    '''
    根据基本URL及请求的字典来拼接新的请求地址
    输入参数：
        url，基础URL，不带参数，如：http://www.local.com/a.php
        queryDict，请求的参数，字典类型 {"id":"1"}
    输出参数：
        http://www.local.com/a.php?id=1
    '''
    return "%s?%s" % (url, dict2Query(queryDict))

def query2Dict(query=""):
    '''
    将query字符串分隔成字典
    输入如：
        a=b
        a=b&c=d
        a=b&c=d&a=c
    输出如：
        {"a":"b"}
        {"a":"b","c":"d"}
    '''
    queryDict = {}
    tmpDict = urlparse.parse_qs(query)
    for key,value in tmpDict.iteritems():
        queryDict[key] = value[0]
    return queryDict

def dict2Query(queryDict={}, isUrlEncode=True):
    '''
    字典转换为query字符串，只针对一维字典
    输入参数：
        {"a":"b"}
        {"a":"b","c":"d"}
    输出数据：
        a=b
        a=b&c=d
    '''
    kvList = []
    query = ""
    if isUrlEncode:
        query = urllib.urlencode(queryDict)
        return query
    else:
        for k in queryDict.keys():
            kvList.append(k + "=" + queryDict[k])
        return "&".join(kvList)

def request(url='', method="GET", body={}, headers={}, redirections=5, timeout=30):
    '''
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
        headers，响应头，字典类型
        body，响应内容
        error，请求不成功时的错误信息
    '''
    returnDict = {"url":url, "method":method, "httpcode":0, "request_headers":{},"request_body":'', "response_headers":{}, "response_body":"", "error":''}
    if not url:
        returnDict['error'] = 'url is empty'
        return returnDict

    #根据传来的参数重新组织数据
    method = method.upper()
    if method=="GET":
        if type(body) == types.DictType:
            url = getUrlByQuerydict(url, body)
            body = ""
    elif method == "POST":
        if type(body) == types.DictType:
            body = dict2Query(body)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        else:
            pass
    else:
        pass

    try:
        http = httplib2.Http(timeout=timeout)
        response_headers, response_body = http.request(url, method, body=body, headers=headers, redirections=redirections)
        returnDict['httpcode'] = response_headers.status
        returnDict['request_headers'] = headers
        returnDict['request_body'] = body
        returnDict['response_headers'] = response_headers
        returnDict['response_body'] = response_body
    except Exception, e:
        returnDict['error'] = e.message
    return returnDict

def formatUrlItem(urlItem = {'url':'', 'method':'GET', 'params':'', 'refer':''}):
    '''
    转换引擎自带的 urlitem 为新插件机制需要的 urlitem ，并对url做初步检查，不符合要求的不再构造，直接返回 False
    输入参数格式如下：
        {'url':'', 'method':'GET', 'params':'', 'refer':''}
    正常返回格式如下：
        {'url':'', 'method':'GET', 'queryDict':{}, 'refer':''}
    函数对url做的检查如下：
        1. 参数不能为空
        2.不能是根目录
        3.如果是get方式，只有一个参数，不能没有“＝”号
        4.不能是文件，即后缀不能是 .js, .css, .doc, .txt, .pdf
    '''
    item = copy.deepcopy(urlItem)
    parse=urlparse.urlparse(item['url'])
    path=parse.path.lower()
    if item['params'] == "" or path=="" or path=="/" or path.find(".js")>=0 or path.find(".css")>=0 or path.find(".doc")>=0 or path.find(".txt")>=0 or path.find(".pdf")>=0 or (item['method'] == 'get' and item['params'].find("=")<0):
        return False
    item['queryDict'] = query2Dict(item['params'])
    del item['params']
    return item

def confirmInject(responseTrue, responseFalse):
    lengthTrue = len(responseTrue['response_body'])
    lengthFalse = len(responseFalse['response_body'])
    lengthDiff = lengthTrue-lengthFalse
    if lengthTrue == 0 or lengthFalse == 0:
        return False

    if lengthDiff/float(lengthTrue) > 0.2:
        return True
    else:
        return False

def getRandomTwoDiffent():
    '''
    获取两个不同的随机数字
    主要用于对 SQL 注入的 payload 做真假值判断
    返回数据类型是元组
    '''
    value1 = random.randint(100, 1000)
    value2 = random.randint(100, 1000)
    if value1 == value2:
        value2 = random.randint(100, 1000)
    return value1,value2

def urlencode(Str=""):
    '''
    对字符串进行url编码
    '''
    return urllib.quote_plus(Str)

def urldecode(Str=""):
    '''
    对字符串进行url解码
    '''
    return urllib.unquote_plus(Str)

def getTagByResponseheaders(headers = {}):
    '''
    从响应头中获取标签信息
    '''
    if headers.has_key('server'):
        server = "" 
        return 
    else:
        return ''

def returnInjectResult(url='', confirm=0, detail='', response={'httpcode':0, 'url':'', 'method':'', 'request_headers':{}, 'request_body':'', 'response_headers':{}, 'response_body':''}, output='', payload=''):
        '''
        检测到注入结果后，格式化输出
        输入信息如下：
            url，请求的url
            confirm，确认漏洞存在，值为 0/1 
            detail,漏洞描述详情
            response，http请求信息，包括5项，分别为：
                httpcode http请求状态码
                url 请求的URL
                method 请求方式
                request_headers 请求头 字典格式
                request_body 请求体
                response_headers 响应头 字典格式
                response_body 响应体
            output，页面输出的额外信息，用于个别插件存储部分信息
        输出信息如下：
            url，请求的url
            confirm，确认漏洞存在，值为 0/1 
            detail,漏洞描述
            httpcode，http请求状态码
            request，http请求实体
            response，响应实体
            output，页面输出的额外信息，用于个别插件存储部分信息
            payload，构造攻击的payload
        '''
        formatResult = {}
        formatResult['url'] = confirm
        formatResult['confirm'] = confirm
        formatResult['detail'] = detail
        formatResult['httpcode'] = response['httpcode']
        formatResult['request'] = getRequest(response['url'], response['method'].upper(), response['request_headers'], response['request_body'])
        formatResult['response'] = getResponse(response['response_headers'], response['response_body'])
        formatResult['output'] = output
        formatResult['payload'] = payload
        return formatResult

def parseCurlCommand(curlCommand=None):
    '''
    解析由浏览器中复制出来的curl命令，转换为相应的字典数据
    '''

    patternUrl = re.compile(r"curl\s'(.*?)'\s")
    patternHeader = re.compile(r"-H\s'(.*?)'\s")
    patternCookieValue = re.compile(r'".*?"')
    patternData = re.compile(r"--data\s'(.*?)'")

    #url
    tmpUrl = patternUrl.findall(curlCommand)
    url = tmpUrl[0]

    #header
    tmpHeader = patternHeader.findall(curlCommand)
    headers = {}
    cookie = ''
    for row in tmpHeader:
        tmp = row.split(': ')
        if tmp[0] == 'Cookie':
            cookie = tmp[1]
        else:
            headers[tmp[0]] = tmp[1]

    #cookie
    cookies = {}
    tmpCookie = cookie.split('; ')
    for row in tmpCookie:
        tmp = row.split("=", 1)
        if patternCookieValue.match(tmp[1]):
            cookies[tmp[0]] = tmp[1].strip('"')
        else:
            cookies[tmp[0]] = tmp[1]

    #data
    data = {}
    tmpData = patternData.findall(curlCommand)
    if tmpData:
        dataLines = tmpData[0].split('&')
        for row in dataLines:
            tmp = row.split("=", 1)
            data[tmp[0]] = tmp[1]
    return {'url':url, 'headers':headers, 'cookies':cookies, 'cookie':cookie, 'data':data}

def writeFile(self, filename = '/tmp/scrapy_default.log', content=''):
    fp = open(filename, 'w')
    fp.write(content)
    fp.close

if __name__ == "__main__":
    pass

