#!/usr/bin/python
# -*- coding: utf-8 -*-
import HTMLParser, sys, time
import json as jsonSys
from engine_lib import yd_json as json
from engine_lib.HttpRequest import *
from db.MysqlDao import *
from engine_utils.common import *

from logger import scanLogger as logger


class SearchSite(threading.Thread):
    def __init__(self, taskId, taskCnf):
        try:
            threading.Thread.__init__(self)
            self.module = self.__class__.__name__
            self.taskId = taskId
            self.assetTaskId = taskCnf['asset_task_id']
            self.taskCnf = taskCnf
            self.sitePorts = [80, 81, 443, 8080]
            self.http = HttpRequest({'timeout': self.taskCnf['web_search_site_timeout']})
            self.htmlParser = HTMLParser.HTMLParser()
            self.ipList = []
            self.dao = MysqlDao()

        except Exception, e:
            logger.exception(e)

    def finish(self):
        try:
            self.dao.updateData('task', {'web_search_site_state': '1'}, {'id': self.taskId})
        except Exception, e:
            logger.exception(e)

    # 更新任务需要扫描的站点
    def updateTaskSites(self, siteObj):
        try:
            logger.debug('start to add new site')
            try:
                scheme, domain, path = getRedirect(
                    "%s://%s%s" % (siteObj['scheme'], siteObj['domain'], siteObj['path']))
            except Exception, e1:
                scheme = siteObj['scheme']
                domain = siteObj['domain']
                path = siteObj['path']
                pass

            if scheme != 'http' and scheme != 'https':
                siteObj['scheme'] = 'http'
            else:
                siteObj['scheme'] = scheme

            if not path or path == '':
                siteObj['path'] = path

            siteExistObj = {'task_id': self.taskId, 'asset_task_id': self.assetTaskId, 'scheme': siteObj['scheme'],
                            'domain': siteObj['domain'], 'path': siteObj['path']}

            if self.dao.getDataCount('sites', siteExistObj) > 0:
                return True

            siteObj['task_id'] = self.taskId
            siteObj['asset_task_id'] = self.assetTaskId
            siteObj['progress'] = ''

            siteId = self.dao.insertData('sites', siteObj)
            if siteId == 0:
                logger.error('add new site to db exception')
                return False

            siteQueue.put(str(siteId))
            ####### use the new spider add by mcj
            self.dao.updateData('spider_url', {'site_id': siteId}, {'task_id': self.taskId})
            self.dao.updateData('spider_url_other', {'site_id': siteId}, {'task_id': self.taskId})
            #############
            ipExistObj = {'task_id': self.taskId, 'asset_task_id': self.assetTaskId, 'ip': siteObj['ip']}

            if self.dao.getDataCount('host_infos', ipExistObj) < 1:
                currentTime = time.strftime("%Y-%m-%d %X", time.localtime())
                hostObj = {'task_id': self.taskId, 'asset_task_id': self.assetTaskId, 'ip': siteObj['ip'],
                           'start_time': currentTime}
                # mcj:insertData() takes exactly 3 arguments (2 given) add argument:host_infos
                self.dao.insertData('host_infos', hostObj)

                taskObj = {'host_scan_state': 0, 'weak_pwd_scan_state': 0, 'port_scan_state': 0}
                self.dao.updateData('task', taskObj, {'id': self.taskId})
        except Exception, e:
            logger.exception(e)

    def searchOtherSiteInIp(self, ip):
        try:
            getSiteByIpUrl = 'http://test.com/dns?ip=%s' % (ip)
            res, content = self.http.request(url)

            if content == '':
                return False
            content = json.read(content)
            if isinstance(content, list) == False:
                return False

            for row in content:
                siteObj = {'scheme': 'http', 'domain': '', 'path': '/', 'ip': ip, 'title': '', 'policy': 1,
                           'include_url': '', 'exclude_url': '', 'cookie': '', 'sub_domain_scan': 0,
                           'ip_domain_scan': 0}

                if row.has_key('domain') == False:
                    continue
                siteObj['domain'] = row['domain']

                if row.has_key('scheme'):
                    siteObj['scheme'] = row['scheme']

                if row.has_key('path'):
                    siteObj['path'] = row['path']

                if row.has_key('title'):
                    siteObj['title'] = row['title']

                self.updateTaskSites(siteObj)

            return True
        except Exception, e:
            logger.exception(e)

    def ifIpAlive(self, ip):
        try:
            try:
                sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sk.settimeout(self.taskCnf['web_scan_timeout'])
                sk.connect((ip, 80))
                sk.close()
                return True
            except Exception, e1:
                sk.close()
                logger.exception(e1)
                return False
        except Exception, e:
            logger.exception(e)
            return False

    def run(self):
        try:
            logger.debug('start to search site')
            # 获取上一次未扫描完成的域名
            logger.debug('taskId %s ' % self.taskId)
            siteIds = self.dao.getUnscandSite(self.taskId, self.assetTaskId)
            logger.debug(siteIds)

            for siteId in siteIds:
                logger.debug('siteQueue put %s ' % siteId)
                siteQueue.put(siteId)

            if self.taskCnf['web_search_site_state'] == 0:
                target = self.taskCnf['target'].encode('utf8')
                if target == '':
                    target = []
                else:
                    target = json.read(target)

                ipList = []

                logger.debug('target: ' + jsonSys.dumps(target))
                for row in target:
                    try:
                        siteObj = {'scheme': 'http', 'domain': '', 'path': '/', 'ip': '', 'title': '', 'policy': '1',
                                   'include_url': '', 'exclude_url': '', 'cookie': '', 'sub_domain_scan': 0,
                                   'ip_domain_scan': 0}

                        if row.has_key('scheme'):
                            siteObj['scheme'] = row['scheme']

                        if row.has_key('domain') == False:
                            logger.error("can not get domain")
                            continue

                        siteObj['domain'] = row['domain']
                        if row.has_key('path'):
                            siteObj['path'] = row['path']

                        if row.has_key('ip'):
                            # 支持配置自定义IP指向
                            ip = row['ip']
                        else:
                            ip = domainToip(siteObj['domain'])

                        if ip == False:
                            logger.error("can not get ip, domain: %s" % (siteObj['domain']))
                            continue

                        siteObj['ip'] = ip

                        if row.has_key('title'):
                            siteObj['title'] = row['title']

                        if row.has_key('policy'):
                            siteObj['policy'] = row['policy']
                        else:
                            siteObj['policy'] = 1

                        if row.has_key('include_url'):
                            siteObj['include_url'] = json.write(row['include_url'])

                        if row.has_key('exclude_url'):
                            siteObj['exclude_url'] = json.write(row['exclude_url'])

                        if row.has_key('cookie'):
                            siteObj['cookie'] = row['cookie']

                        # 是否扫描二级域名
                        if row.has_key('sub_domain_scan'):
                            siteObj['sub_domain_scan'] = row['sub_domain_scan']

                        # 该IP的其他域名扫描
                        if row.has_key('ip_domain_scan'):
                            siteObj['ip_domain_scan'] = row['ip_domain_scan']

                        if siteObj['ip_domain_scan'] == 1:
                            # 根据IP获取IP下的域名
                            if ip not in ipList:
                                otherSites = self.searchOtherSiteInIp(ip)
                                target.extend(otherSites)
                                ipList.append(ip)

                        self.updateTaskSites(siteObj)
                    except Exception, ee:
                        logger.error(ee)

            self.finish()

            logger.debug('end to search site')
        except Exception, e:
            logger.exception(e)
            self.finish()
