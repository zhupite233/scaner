#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re

from engine_utils.DictData import sqlErrorDict
#from engine_utils.InjectUrlLib import *
from engine_utils.InjectUrlLib import confirmInject
from engine_utils.InjectUrlLib import getRandomTwoDiffent
from engine_utils.InjectUrlLib import getHeaderdictByPayload
from engine_utils.yd_http import request
from engine_utils.InjectUrlLib import getUrlsByQuerydictBodydictPayloads
from engine.engine_utils.common import getResponse
from engine.engine_utils.common import getRequest

class InjectSql:

    def checkFirstForGet(self, url="", queryDict={}, bodyDict={}, headers={}, theKey="", method="GET"):
        '''
        第一次检测，主要用于检测数据库类型，粗略的SQL注入检测
        '''
        responseList = []
        #检查单引号'，反斜线\ ，主要用于判断SQL报错，判断数据库类型
        urls = getUrlsByQuerydictBodydictPayloads(url, queryDict, bodyDict)
        responseBase = request(url=urls[0]['url'], body=urls[0]['body'], headers=headers, method=method)

        #判断httpcode状态位
        if responseBase['httpcode'] != 200:
            return False

        #检测数据库类型，数据库类型放在 self.database 变量中
        self.checkDatabase2(url, queryDict, bodyDict, headers, method=method)

        '''
        检查key对应的值是数字型还是字符串型
        如果全部是数字，则先用数字型判断，如果能确认SQL注入，则直接返回
        直接用正则匹配的方式来判断，并不准确，因此没能确认SQL注入时，后面依然使用字符串型及搜索型进行尝试
        '''
        if (queryDict.has_key(theKey) and re.match(r'(\d+)', queryDict[theKey])) or (bodyDict.has_key(theKey) and re.match(r'(\d+)', bodyDict[theKey])):
            result = self.checkInjectNumericForCommon(url, queryDict, bodyDict, headers, theKey, method, responseBase)
            if result:
                return result

        #字符串型
        result = self.checkInjectStrForCommon(url, queryDict, bodyDict, headers, theKey, method)
        if result:
            return result

        #搜索型
        result = self.checkInjectSearchForCommon(url, queryDict, bodyDict, headers, theKey, method)
        if result:
            return result
        return False

    def checkFirst(self, url="", queryDict={}, bodyDict={}, headers={}, theKey="", method="GET"):
        '''
        第一次检测，主要用于检测数据库类型，粗略的SQL注入检测
        '''
        responseList = []
        #检查单引号'，反斜线\ ，主要用于判断SQL报错，判断数据库类型
        urls = getUrlsByQuerydictBodydictPayloads(url, queryDict, bodyDict)
        responseBase = request(url=urls[0]['url'], body=urls[0]['body'], headers=headers, method=method)

        #判断httpcode状态位
        if responseBase['httpcode'] != 200:
            return False

        #检测数据库类型，数据库类型放在 self.database 变量中
        self.checkDatabase2(url, queryDict, bodyDict, headers, method=method)

        '''
        检查key对应的值是数字型还是字符串型
        如果全部是数字，则先用数字型判断，如果能确认SQL注入，则直接返回
        直接用正则匹配的方式来判断，并不准确，因此没能确认SQL注入时，后面依然使用字符串型及搜索型进行尝试
        '''
        if (queryDict.has_key(theKey) and re.match(r'(\d+)', queryDict[theKey])) or (bodyDict.has_key(theKey) and re.match(r'(\d+)', bodyDict[theKey])):
            result = self.checkInjectNumericForCommon(url, queryDict, bodyDict, headers, theKey, method, responseBase)
            if result:
                return result

        #字符串型
        result = self.checkInjectStrForCommon(url, queryDict, bodyDict, headers, theKey, method)
        if result:
            return result

        #搜索型
        result = self.checkInjectSearchForCommon(url, queryDict, bodyDict, headers, theKey, method)
        if result:
            return result
        return False

    def checkFirstForHeader(self, url='', headers={}):
        '''
        Header头注入，目前支持：User-Agent, Referer, Cookie，Header注入默认使用GET方式请求
        输入参数：
            url，请求的URL
        输出数据：
            json格式的注入检测结果
        '''

        responseList = []
        result = self.checkFirstForUseragent(url=url, headers=headers)
        if result:
            return result
        result = self.checkFirstForReferer(url=url, headers=headers)
        if result:
            return result
        return False

    def checkFirstForUseragent(self, url='', headers={}):
        '''
        Header头User-Agent注入
        输入参数：
            url，请求的URL
        输出数据：
            json格式的注入检测结果
        '''
        theKey="User-Agent"
        responseList = []
        responseBase = request(url=url, headers=headers)
        headerPayloads = getHeaderdictByPayload(headerDict=headers, theKey=theKey, payloads=["'", "''", "'''", "\\", "\\", "\\\\\\"])
        for headerPayload in headerPayloads:
            response = request(url=url, headers=headerPayload)

            databaseType = self.checkDatabase(body=response['response_body'])
            if databaseType:
                resultCheck = self.returnInjectResult(url=response['url'], confirm=True, detail="存在注入的URL：%s\n该注入类型为：Header头提交方式的数字型注入" % (response['url']), response=response)
                responseList.append(resultCheck)
                return responseList
        return False

    def checkFirstForReferer(self, url='', headers={}):
        '''
        Header头Referer注入
        输入参数：
            url，请求的URL
        输出数据：
            json格式的注入检测结果
        '''
        theKey="Referer"
        responseList = []
        responseBase = request(url=url)
        headerPayloads = getHeaderdictByPayload(headerDict=headers, theKey=theKey, payloads=["'", "''", "'''", "\\", "\\", "\\\\\\"])
        for headerPayload in headerPayloads:
            response = request(url=url, headers=headerPayload)
            databaseType = self.checkDatabase(body=response['response_body'])
            if databaseType:
                resultCheck = self.returnInjectResult(url=response['url'], confirm=True, detail="存在注入的URL：%s\n该注入类型为：Header头提交方式的数字型注入" % (response['url']), response=response)
                responseList.append(resultCheck)
                return responseList
        return False

    def checkDatabase(self, body=''):
        '''
        检测数据库类型，为粗略检测
        '''
        for dbname in sqlErrorDict:
            for row in sqlErrorDict[dbname]:
                if row['type'] == 'normal':
                    if body.find(row['search']) >= 0:
                        return dbname
                elif row['type'] == 'regular':
                    if re.search(row['search'], body) >= 0:
                        return dbname
                else:
                    pass
        return ''

    def checkDatabase2(self, url, queryDict = {}, bodyDict = {}, headers = {}, method="GET"):
        payloads=["'", "''", "'''", "\\", "\\", "\\\\\\"]
        #如果已经检测到数据库类型，直接返回结果
        if hasattr(self, 'database'):
            return self.database

        #URL是否已经进行过数据库类型检查
        if hasattr(self, 'checkedDatabaseUrls'):
            if url in self.checkedDatabaseUrls:
                return False
        else:
            self.checkedDatabaseUrls = []
            self.checkedDatabaseUrls.append(url)

        #构造待请求的URL
        urls = getUrlsByQuerydictBodydictPayloads(url, queryDict, bodyDict, payloads=payloads)
        #遍历URL，并判断数据类型
        self.database = ""
        for row in urls:
            response = request(url=row['url'], body=row['body'], headers=headers, method=method)
            for dbname in sqlErrorDict:
                for row in sqlErrorDict[dbname]:
                    if row['type'] == 'normal':
                        if response['response_body'].find(row['search']) >= 0:
                            self.database = dbname
                    elif row['type'] == 'regular':
                        if re.search(row['search'], response['response_body']) >= 0:
                            self.database = dbname
                    else:
                        pass
                break
        if self.database:
            return self.database
        else:
            return False

    def checkInjectNumericForCommon(self, url="", queryDict={}, bodyDict={}, headers={}, theKey="", method="GET", responseBase={}):
        '''
        通用版 数字型SQL注入检测
        '''
        '''
        数字转换为表达式类型，准确度较高
        将数字转换为表达式后，结果是否一致，一致，则50％＋有SQL注入
        id=1
        id=9001-9000
        '''
        responseList = []
        payloads = []
        if queryDict.has_key(theKey):
            value = int(queryDict[theKey]) + 3000
            payloads.append(str(value) + "-3000")
        if bodyDict.has_key(theKey):
            value = int(bodyDict[theKey]) + 3000
            payloads.append(str(value) + "-3000")
        injectWay="replace"
        urls = getUrlsByQuerydictBodydictPayloads(url, queryDict, bodyDict, payloads, theKey, injectWay)
        row = urls[0]
        responseFalse = request(url=row['url'], body=row['body'], headers=headers, method=method)
        if responseBase['httpcode'] == 200 and responseFalse['httpcode'] == 200 and confirmInject(responseTrue=responseBase, responseFalse=responseFalse):
            resultCheck = self.returnInjectResult(url=url, confirm=True, detail="存在注入的URL：%s\n该注入类型为：%s提交方式的数字型注入" % (responseFalse['url'], method), response=responseFalse)
            responseList.append(resultCheck)
            return responseList
            #resultConfirm = confirmInjectNumericForMysql(url=url, queryDict=queryDict, theKey=theKey)
            #if resultConfirm:
            #    return resultConfirm
            #else:
            #    return False

        '''
        数字真假值判断，误报率 30%
        通过数字等于或不等于，根据内容是否一致来判断SQL注入的概率
        AND 2142=6509
        AND 1265=1265
        '''
        value1,value2 = getRandomTwoDiffent()
        payloadStr1 = " AND " + str(value1) + "=" + str(value1)
        payloadStr2 = " AND " + str(value1) + "=" + str(value2)
        payloads = [payloadStr1, payloadStr2]
        injectWay = "append"
        urls = getUrlsByQuerydictBodydictPayloads(url, queryDict, bodyDict, payloads, theKey, injectWay)
        responseTrue = request(url=urls[0]['url'], body=urls[0]['body'], headers=headers, method=method)
        responseFalse = request(url=urls[1]['url'], body=urls[1]['body'], headers=headers, method=method)
        if responseTrue['httpcode'] == 200 and responseFalse['httpcode'] == 200 and confirmInject(responseTrue=responseTrue, responseFalse=responseFalse):
            resultCheck = self.returnInjectResult(url=url, confirm=True, detail="存在注入的URL：%s\n该注入类型为：%s提交方式的数字型注入" % (responseFalse['url'], method), response=responseFalse)
            responseList.append(resultCheck)
            return responseList

        '''
        数字真假值及mysql中止符，误报率 50%
        通过数字等于或不等于，根据内容是否一致来判断SQL注入的概率
        --在SQL中代表中止符
        AND 2142=6509-- sMWn
        AND 1265=1265-- sMWn
        '''
        payloadStr1 = " AND " + str(value1) + "=" + str(value1) + "-- sMWn"
        payloadStr2 = " AND " + str(value1) + "=" + str(value2) + "-- sMWn"
        payloads = [payloadStr1, payloadStr2]
        injectWay = "append"
        urls = getUrlsByQuerydictBodydictPayloads(url, queryDict, bodyDict, payloads, theKey, injectWay)
        responseTrue = request(url=urls[0]['url'], body=urls[0]['body'], headers=headers, method=method)
        responseFalse = request(url=urls[1]['url'], body=urls[1]['body'], headers=headers, method=method)
        if responseTrue['httpcode'] == 200 and responseFalse['httpcode'] == 200 and confirmInject(responseTrue=responseTrue, responseFalse=responseFalse):
            resultCheck = self.returnInjectResult(url=url, confirm=True, detail="存在注入的URL：%s\n该注入类型为：%s提交方式的数字型注入" % (responseFalse['url'], method), response=responseFalse)
            responseList.append(resultCheck)
            return responseList
        return False

    def checkInjectStrForCommon(self, url="", queryDict={}, bodyDict={}, headers={}, theKey="", method="GET"):
        '''
        通用版 字符型SQL注入检测
        '''
        '''
        字符型真假值，误报率 50%
        通过数字等于或不等于，根据内容是否一致来判断SQL注入的概率
        ' AND 8796=9880 AND 'kHiu'='kHiu
        ' AND 1265=1265 AND 'KoIp'='KoIp
        '''
        responseList = []
        value1,value2 = getRandomTwoDiffent()
        payloadStr1="' AND " + str(value1) + "=" + str(value1) + " AND 'abcd'='abcd"
        payloadStr2="' AND " + str(value2) + "=" + str(value2) + " AND 'efgh'='efgh"
        payloads = [payloadStr1, payloadStr2]
        injectWay = "append"
        urls = getUrlsByQuerydictBodydictPayloads(url, queryDict, bodyDict, payloads, theKey, injectWay)
        responseTrue = request(url=urls[0]['url'], body=urls[0]['body'], headers=headers, method=method)
        responseFalse = request(url=urls[1]['url'], body=urls[1]['body'], headers=headers, method=method)
        if responseTrue['httpcode'] == 200 and responseFalse['httpcode'] == 200 and confirmInject(responseTrue=responseTrue, responseFalse=responseFalse):
            resultCheck = self.returnInjectResult(url=url, confirm=True, detail="存在注入的URL：%s\n该注入类型为：%s提交方式的数字型注入" % (responseFalse['url'], method), response=responseFalse)
            responseList.append(resultCheck)
            return responseList
        return False

    def checkInjectSearchForCommon(self, url="", queryDict={}, bodyDict={}, headers={}, theKey="", method="GET"):
        '''
        通用版 搜索型SQL注入检测
        '''
        '''
        搜索型真假值，误报率 50%
        通过数字等于或不等于，根据内容是否一致来判断SQL注入的概率
        %' AND 1819=4502 AND '%'='
        %' AND 1265=1265 AND '%'='
        '''
        responseList = []
        value1,value2 = getRandomTwoDiffent()
        payloadStr1="%' AND " + str(value1) + "=" + str(value1) + " AND '%'='"
        payloadStr2="%' AND " + str(value1) + "=" + str(value2) + " AND '%'='"
        payloads = [payloadStr1, payloadStr2]
        injectWay = "append"
        urls = getUrlsByQuerydictBodydictPayloads(url, queryDict, bodyDict, payloads, theKey, injectWay)
        responseTrue = request(url=urls[0]['url'], body=urls[0]['body'], headers=headers, method=method)
        responseFalse = request(url=urls[1]['url'], body=urls[1]['body'], headers=headers, method=method)
        if responseTrue['httpcode'] == 200 and responseFalse['httpcode'] == 200 and confirmInject(responseTrue=responseTrue, responseFalse=responseFalse):
            resultCheck = self.returnInjectResult(url=url, confirm=True, detail="存在注入的URL：%s\n该注入类型为：%s提交方式的数字型注入" % (responseFalse['url'], method), response=responseFalse)
            responseList.append(resultCheck)
            return responseList
        return False

    def confirmInjectNumericForMysql(self, url="", queryDict={}, bodyDict={}, headers={}, theKey="", method="GET"):
        '''
        确认数字型SQL注入 
        '''
        responseList = []
        payloadStr1="updatexml(1,concat(0x3a,(select%20\"inject_integer_tester\")), 1)"
        payloads = [payloadStr1]
        injectWay = "append"
        urls = getUrlsByQuerydictBodydictPayloads(url, queryDict, bodyDict, payloads, theKey, injectWay)
        response = request(url=urls[0]['url'], body=urls[0]['body'], headers=headers, method=method)
        if response['httpcode'] == 200 and response['response_body'].find('inject_integer_tester')>0:
            resultCheck = self.returnInjectResult(url=url, confirm=True, detail="存在注入的URL：%s\n该注入类型为：%s提交方式的数字型注入" % (response['url'], method), response=response)
            responseList.append(resultCheck)
            return responseList
        return False

    def confirmInjectStrForMysql(self, url="", queryDict={}, theKey="", method="GET"):
        pass

    def confirmInjectSearchForMysql(self, url="", queryDict={}, theKey="", method="GET"):
        pass

    def confirmInjectForMssql(self, checkType=[]):
        '''
        检测数字型SQL注入，针对Mssql
        '''
        pass

    def confirmInjectForOracle(self, checkType=[]):
        '''
        检测搜索型SQL注入，针对Oracle
        '''
        pass

    def checkSqlError(self, body="", dbList=[], msgs=[]):
        '''
        检查SQL报错，并返回报错信息，格式如下：
        {'status':False, "dbname":"", "dberror":"", "seemerror":""}
        '''
        result = {'status':False, "dbname":"", "dberror":"", "seemerror":""}
        if not body:
            return result
        for dbname in dbList:
            for row in sqlErrorDict[dbname]:
                if row['type'] == 'normal':
                    if body.find(row['search']) >= 0:
                        result['status'] = True
                        result['dbname'] = dbname
                        result['dberror'] = row['search']
                        return result
                elif row['type'] == 'regular':
                    if re.search(row['search'], body) >= 0:
                        result['status'] = True
                        result['dbname'] = dbname
                        result['dberror'] = row['search']
                        return result
                else:
                    pass

        for msg in msgs:
            if body.find(msg) >= 0:
                result['status'] = True
                result['dbname'] = 'mysql'
                result['dberror'] = msg
                return result

        return result

    def returnInjectResult(self, url='', confirm=0, detail='', response={'httpcode':0, 'url':'', 'method':'', 'request_headers':{}, 'request_body':'', 'response_headers':{}, 'response_body':''}, output='', payload=''):
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

