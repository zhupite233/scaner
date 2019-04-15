#!/usr/bin/python
# -*- coding: utf-8 -*-
import time, sys
from  threading import Thread
from Queue import Queue
from engine_utils.common import *
from db.MysqlDao import *
from engine_lib.HttpRequest import *

from logger import scanLogger as logger

class ScanScriptForUrl:
    def __init__(self, scanCnf):
        try:
            self.module = self.__class__.__name__
            self.scanCnf = scanCnf
            self.taskId = scanCnf['taskId']
            self.assetTaskId = scanCnf['assetTaskId']
            self.siteId = scanCnf['siteId']
            self.vulId = scanCnf['vulId']
            self.scriptThread = scanCnf['scriptThread']
            self.ip = scanCnf['ip']
            self.scheme = scanCnf['scheme']
            self.domain = scanCnf['domain']
            self.path = scanCnf['path']
            self.cookie = scanCnf['cookie']
            self.endTime = scanCnf['endTime']
            self.maxTimeoutCount = scanCnf['maxTimeoutCount']
            self.level = scanCnf['level']
            self.script = scanCnf['script']
            self.webTimeout = scanCnf['webTimeout']
            self.dao = MysqlDao()
            self.urlQueue = scanCnf.get('queue')
            self.threadLock = threading.Lock()
            self.excludeUrl = scanCnf['excludeUrl']
            self.timeoutCount = 0

        except Exception, e:
            logger.error(e)

    def checkTimeOut(self):
        if self.timeoutCount > self.maxTimeoutCount:
            return False
        if self.endTime < time.time():
            return False
        return True

    def checkExcludeItemUrl(self, modUrl, url):
        try:
            if modUrl.find("?") > 0:
                r1 = re.compile(modUrl.split("?")[0].replace("*","(.*?)"))
                res = re.findall(r1, url.split("?")[0])
                if res and len(res) > 0:
                    mod_params = modUrl.split("?")[1]
                    if modUrl == "*" and url.find("?") < 0:
                        return True
                    if url.find("?") > 0:
                        params = url.split("?")[1]
                        mod_params_list = mod_params.split("&")
                        for row in mod_params_list:
                            r2 = re.compile(row.replace("*","(.*?)"))
                            res = re.findall(r2, params)
                            if res and len(res) > 0:
                                pass
                            else:
                                return False
                        return True
            else:
                r1 = re.compile(modUrl.replace("*","(.*?)"))
                res = re.findall(r1, url.split("?")[0])
                if res and len(res) > 0:
                    return True

            return False
        except Exception,e:
            logger.error(e)
            return False

    def checkExcludeUrl(self, excludeUrl, url):
        try:
            for row in excludeUrl:
                if row.find("http://") < 0 and row.find("https://") < 0:
                    continue
                if self.checkExcludeItemUrl(row, url):
                    return True

            return False
        except Exception,e:
            logger.error(e)
            return False

    def updateResult(self, resList):
        try:
            for item in resList:
                try:
                    url = item['url']
                    if item.has_key('vul_id'):
                        vulId = item['vul_id']
                    elif item.has_key('vulId'):
                        vulId = item['vulId']
                    else:
                        vulId = self.vulId
                    level = item['level']
                    detail = item['detail']
                    output = item['output']

                    searchObj = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'site_id':self.siteId,'url':url,'vul_id':vulId,'level':level,'detail':detail}

                    if self.dao.getDataCount('web_result', searchObj) > 0:
                        continue

                    resDb = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'site_id':self.siteId,'url':url,'level':level,'detail':detail,'output':output,'vul_id':vulId}
                    resId = self.dao.insertData('web_result', resDb)

                    if resId < 1:
                        continue

                    #resDataDb = {'web_result_id':resId,'task_id':self.taskId,'asset_task_id':self.assetTaskId,'site_id':self.siteId,'request':item['request'],'response':item['response']}
                    resDataDb = {'web_result_id':resId,'task_id':self.taskId,'asset_task_id':self.assetTaskId,'site_id':self.siteId,'request':item['request'],'response':item['response'], 'payload':item['payload'], 'params':item['params']}
                    self.dao.insertData('web_result_data', resDataDb)

                except Exception,e1:
                    logger.error(e1)
        except Exception, e:
            logger.error(e)

    def main(self):
        try:
            # add params domain use for init host_scan of the header by mcj
            http = HttpRequest({'domain': self.domain, 'timeout':self.webTimeout,'follow_redirects':True,'cookie':self.cookie})

            logger.debug("from plugins.%s import *" % (self.script))
            exec("from plugins.%s import *" % (self.script))

            #临时计数器
            temp_num = 0
            #开始扫描
            while True:
                try:
                    if self.urlQueue.qsize() < 1:
                        break
                    list = []
                    try:
                        item = self.urlQueue.get_nowait()
                    except Exception, e2:
                        break
                    
                    url = item['url']
                    if item['method'] == 'get' and item['params'] != '':
                        url = "%s?%s" % (url, item['params'])
                    if self.checkExcludeUrl(self.excludeUrl,url):
                        continue

                    list = run_url(http, self.scanCnf, item)

                    if list and len(list) > 0:
                        temp_num += len(list)
                        
                        #对于邮件信息泄露和HTML注释信息泄露做了部分特殊处理
                        if self.script in ['HtmlSourceLeakScript','EmailDiscloseScript'] and temp_num > 10:
                            break

                        self.threadLock.acquire()
                        self.updateResult(list)
                        self.threadLock.release()
                except Exception, e1:
                    logger.error(e1)
        except Exception,e:
            logger.error(e)
    
    def start(self):
        try:
            if self.script == "":
                return
            list = []

            for i in range(self.scriptThread):
                list.append(Thread(target=self.main, args=()))
            for t in list:
                t.start()
            for t in list:
                t.join()
        except Exception,e:
            logger.error(e)

