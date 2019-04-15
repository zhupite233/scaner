#!/usr/bin/python
#-*-encoding:UTF-8-*-
# 线程非安全，停用
# MySQLdb 就是线程非安全的，不适用
import sys
import MySQLdb
#使用全新的配置文件
from engineConfig import *

from logger import scanLogger as logger

class MysqlDao:
    def __init__(self, host = '', database = '', user = '', passwd = ''): 
        try:
            if host == '' or database == '' or user == '' or passwd == '':
                self.host = SCANER_DB_HOST
                self.database = SCANER_DB_DATABASE
                self.user = SCANER_DB_USER
                self.passwd = SCANER_DB_PASSWORD
            else:
                self.host = host
                self.database = database
                self.user = user
                self.passwd = passwd
            self.conn = ''
            self.cursor = ''
            self.module = self.__class__.__name__
        except Exception, e:
            logger.exception(e)

    def mysqlConnect(self):
        try:
	    '''为避免MYSQL超时，解决每次操作时，连接数据库'''
            self.mysqlClose()
            self.reconnect()
            return True
	    '''
            if self.conn == '' or self.cursor == '':
                self.reconnect()
            else:
                try:
                    self.conn.ping()
                except MySQLdb.OperationalError, e1:
                    self.mysqlClose()
                    self.reconnect()
                    logger.exception(e1)
            return True
	    '''
        except Exception, e:
            logger.exception(e)

    def reconnect(self):
        try:
            self.conn = MySQLdb.connect(self.host, self.user, self.passwd , db = self.database, charset = "utf8")
            self.cursor = self.conn.cursor(MySQLdb.cursors.DictCursor)
            return True
        except Exception, e:
            logger.exception(e)
            return False

    def mysqlClose(self):
        try:
            if self.conn != '' and self.cursor != '':
                self.cursor.close()
                self.conn.close()
            self.conn = ''
            self.cursor = ''
            return True
        except Exception, e:
            logger.exception(e)
            return False

    #获取资产管理扫描任务ID
    def getAssetTaskId(self, taskId):
        try:
            if self.mysqlConnect():
                sql = "select `asset_task_id` from `task` where `id` = '%s'" % (taskId)
                self.cursor.execute(sql)
                res = self.cursor.fetchone()
                if res and len(res) > 0:
                    return res['asset_task_id']
            return False
        except Exception, e:
            logger.exception(e)
            return False

    def getDataBySql(self, sql):
        try:
            if self.mysqlConnect():
                self.cursor.execute(sql)
                res = self.cursor.fetchall()
                if res and len(res) > 0:
                    return res
            return []
        except Exception, e:
            logger.exception(e)
            return []

    def getRowDataBySql(self, sql):
        try:
            if self.mysqlConnect():
                self.cursor.execute(sql)
                res = self.cursor.fetchone()
                if res and len(res) > 0:
                    return res
            return None
        except Exception, e:
            logger.exception(e)
            return None

    #根据任务ID获取扫描任务数据
    def getTaskData(self, taskId, columns = '*'):
        try:
            if self.mysqlConnect():
                sql = "select %s from task where id = %s" % (columns, taskId)
                self.cursor.execute(sql)
                res = self.cursor.fetchone()
                if res and len(res) > 0:
                    return res
            return False
        except Exception, e:
            logger.exception(e)
            return False

    #获取扫描站点配置
    def getSiteData(self, siteId, columns = '*'):
        try:
            if self.mysqlConnect():
                sql = "select * from sites where id = '%s'" % (siteId)
                self.cursor.execute(sql)
                res = self.cursor.fetchone()
                if res and len(res) > 0:
                    return res
        except Exception, e:
            logger.exception(e)
        return None

    def getData(self, tablename, where, columns = '*'):
        try:
            if self.mysqlConnect():
                whereSql = ' 1 = 1 '
                values = []
                for k in where:
                    whereSql = "%s and `%s` = %s" % (whereSql, k, '%s')
                    values.append(where[k])
                #end for
                sql = "select %s from %s where %s" % (columns, tablename, whereSql)
                self.cursor.execute(sql, tuple(values))
                res = self.cursor.fetchall()
                if res and len(res) > 0:
                    return res
        except Exception, e:
            logger.exception(e)
        return []

    def getRowData(self, tablename, where, columns = '*'):
        try:
            if self.mysqlConnect():
                whereSql = ' 1 = 1 '
                values = []
                for k in where:
                    whereSql = "%s and `%s` = %s" % (whereSql, k, '%s')
                    values.append(where[k])
                sql = "select %s from %s where %s" % (columns, tablename, whereSql)
                self.cursor.execute(sql, tuple(values))
                res = self.cursor.fetchone()
                if res and len(res) > 0:
                    return res
        except Exception, e:
            logger.exception(e)
        return None

    def updateHostWebScanState(self, taskId, assetTaskId, ip):
        try:
            if self.mysqlConnect():
                sql = "update host_infos set `web_scan_state` = '1' where (select count(id) from sites where `state` <> '1' and `ip` = '%s' and task_id = '%s' and `asset_task_id` = '%s') = 0 and `ip` = '%s' and task_id = '%s' and `asset_task_id` = '%s'" % (ip, taskId, assetTaskId, ip, taskId, assetTaskId)
                self.cursor.execute(sql)
                self.conn.commit()
        except Exception, e:
            logger.exception(e)

    def getSiteExceptionCount(self, siteId):
        try:
            if self.mysqlConnect():
                sql = "select `exception_count` from sites where id = '%s'" % (siteId)
                self.cursor.execute(sql)
                res = self.cursor.fetchone()
                if res and res.has_key('exception_count'):
                    return res['exception_count']
            return 0
        except Exception, e:
            logger.exception(e)
            return 0

    #更新数据库信息
    def updateData(self, tablename, data, where):
        try:
            if self.mysqlConnect():
                values = []

                updateSql = ''
                for k in data:
                    if updateSql == '':
                        updateSql = "`%s` = %s" % (k, '%s')
                    else:
                        updateSql = "%s, `%s` = %s" % (updateSql, k, '%s')
                    values.append(data[k])

                whereSql = ''
                for k in where:
                    if whereSql == '':
                        whereSql = "`%s` = %s" % (k, '%s')
                    else:
                        whereSql = "%s and `%s` = %s" % (whereSql, k, '%s')
                    values.append(where[k])

                sql = "update `%s` set %s where %s" % (tablename, updateSql, whereSql)
                self.cursor.execute(sql, tuple(values))
                self.conn.commit()

                return True
            return False
        except Exception, e:
            logger.exception(e)
            return False

    def deleteData(self, tablename, where):
        try:
            if self.mysqlConnect():
                values = []
                whereSql = ''
                for k in where:
                    if whereSql == '':
                        whereSql = "`%s` = %s" % (k, '%s')
                    else:
                        whereSql = "%s and `%s` = %s" % (whereSql, k, '%s')
                    values.append(where[k])

                sql = "delete from %s where %s" % (tablename, whereSql)
                self.cursor.execute(sql, tuple(values))
                self.conn.commit()

                return True
        except Exception, e:
            logger.exception(e)
        return False

    #获取数据记录数
    def getDataCount(self, tablename, where):
        try:
            if self.mysqlConnect():
                whereSql = ''
                for k in where:
                    if whereSql == '':
                        whereSql = "`%s` = '%s'" % (k, where[k])
                    else:
                        whereSql = "%s and `%s` = '%s'" % (whereSql, k, where[k])

                sql = "select count(id) as c from %s where %s" % (tablename, whereSql)
                self.cursor.execute(sql)
                res = self.cursor.fetchone()
                if res and len(res):
                    return res['c']
                
            return 0
        except Exception, e:
            logger.exception(e)
            return 0

    #获取抓取的URL数量
    def getSpiderUrlCount(self, siteId = 0, url = '', params = '', method = ''):
        try:
            if self.mysqlConnect():
                sql = "select count(id) as c from spider_url where `site_id`=%s and `url`=%s and `params`=%s and `method`=%s"
                sequence = (siteId, url, params, method)
                self.cursor.execute(sql, sequence)
                res = self.cursor.fetchone()
                if res and len(res):
                    return res['c']
                
            return 0
        except Exception, e:
            logger.exception(e)

    #获取抓取的URL数量
    def getSpiderUrlOtherCount(self, siteId = 0, url = '', params = '', method = ''):
        try:
            if self.mysqlConnect():
                sql = "select count(id) as c from spider_url_other where `site_id`=%s and `url`=%s and `params`=%s and `method`=%s"
                sequence = (siteId, url, params, method)
                self.cursor.execute(sql, sequence)
                res = self.cursor.fetchone()
                if res and len(res):
                    return res['c']
            return 0
        except Exception, e:
            logger.exception(e)

    #插入数据
    def insertData(self, tablename, data):
        try:
            if self.mysqlConnect():
                columns = []
                values = []
                valuesTuple = []

                for key in data:
                    columns.append('`' + key + '`')
                    values.append('%s')
                    valuesTuple.append(data[key])

                sql = "insert into %s (%s) values (%s)" % (tablename, ",".join(columns), ",".join(values))
		#logger.debug(sql)
		#logger.debug(tuple(valuesTuple))
                self.cursor.execute(sql, tuple(valuesTuple))
                self.conn.commit()

                sql = "select LAST_INSERT_ID() as id"
                self.cursor.execute(sql)
                self.conn.commit()
                res = self.cursor.fetchone()
                if res and len(res) > 0 and res['id'] > 0:
                    return res['id']

            return 0
        except Exception, e:
            logger.exception(e)
            return 0

    def getUnscandSite(self, taskId, assetTaskId = 0):
        try:
            siteIds = []
            sql = "select `id` from `sites` where `state` <> '1' and `task_id` = '%s' and `asset_task_id` = '%s'" % (taskId, assetTaskId)
            if self.mysqlConnect():
                self.cursor.execute(sql)
                self.conn.commit()
                res = self.cursor.fetchall()
                if res and len(res) > 0:
                    for row in res:
                        siteIds.append(str(row['id']))

            return siteIds
        except Exception, e:
            logger.exception(e)
            return []

    def getWebVulByPolicy(self, policyId):
        try:
            if self.mysqlConnect():
                vulList = []
                sql = "select `vul_id`,`level`,`vul_name`,`scan_type`,`script` from `web_vul_list` where `vul_id` in (select `vul_id` from `web_vul_policy_ref` where `policy_id` = '%s') order by `priority` asc" % (str(policyId))
                self.cursor.execute(sql)
                res = self.cursor.fetchall()
                # tuple 转 list 有何意义 mcj
                if res and len(res) > 0:
                    for row in res:
                        vulList.append(row)
                return vulList
        except Exception, e:
            logger.exception(e)
        return []

    def getUrlList(self, siteId):
        try:
            if self.mysqlConnect():
                sql = "select * from spider_url where site_id = '%s'" % (siteId)
                self.cursor.execute(sql)
                res = self.cursor.fetchall()
                if res and len(res) > 0:
                    return res
        except Exception, e:
            logger.exception(e)
        return []

    def cleanWebScan(self, taskId, assetTaskId):
        try:
            if self.mysqlConnect():
                #清空扫描任务字段
                sql = "update `task` set `web_scan_state` = '0', `web_search_site_state` = '0' where `id` = '%s' " % (taskId)
                self.cursor.execute(sql)
                
                #清空扫描域名记录
                if assetTaskId > 0:
                    sql = "delete from `sites` where `task_id` = '%s' and `asset_task_id` = '%s'" % (taskId, assetTaskId)
                else:
                    sql = "delete from `sites` where `task_id` = '%s'" % (taskId)
                self.cursor.execute(sql)
                
                #清空Web扫描结果
                if assetTaskId > 0:
                    sql = "delete from `web_result` where `task_id` = '%s' and `asset_task_id` = '%s'" % (taskId, assetTaskId)
                else:
                    sql = "delete from `web_result` where `task_id` = '%s'" % (taskId)
                self.cursor.execute(sql)

                #清空Web扫描报文记录
                if assetTaskId > 0:
                    sql = "delete from `web_result_data` where `task_id` = '%s' and `asset_task_id` = '%s'" % (taskId, assetTaskId)
                else:
                    sql = "delete from `web_result_data` where `task_id` = '%s'" % (taskId)
                self.cursor.execute(sql)
                
                #清空扫描的URL记录结果
                if assetTaskId > 0:
                    sql = "delete from `spider_url` where `task_id` = '%s' and `asset_scan_id` = '%s'" % (taskId, assetTaskId)
                else:
                    sql = "delete from `spider_url` where `task_id` = '%s'" % (taskId)
                self.cursor.execute(sql)

                self.conn.commit()

                return True
            else:
                return False
        except Exception, e:
            logger.exception(e)
            return False

mysqlDao = MysqlDao()

if __name__ == '__main__':
    if mysqlDao.mysqlConnect():
        print 'mysql connect success'
    else:
        print 'mysql connect error'

