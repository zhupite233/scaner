#!/usr/bin/python
# -*- coding: utf-8 -*-
import re, sys
from engine_utils.common import *
from db.MysqlDao import *
from engine_lib.HttpRequest import *

from logger import scanLogger as logger

class ScanScriptForDomain:
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
            self.timeoutCount = 0

        except Exception, e:
            logger.error(e)

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

    def start(self):
        try:
            if self.script == "":
                return
            # add params domain use for init host_scan of the header by mcj
            http = HttpRequest({'domain': self.domain, 'timeout':self.webTimeout,'follow_redirects':True})
            logger.debug("from plugins.%s import *" % (self.script))
            exec("from plugins.%s import *" % (self.script))
            
            #开始扫描
            list = run_domain(http, self.scanCnf)
            if list and len(list) > 0:
                self.updateResult(list)

        except Exception,e:
            logger.error(e)

