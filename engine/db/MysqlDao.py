#!/usr/bin/python
#-*-encoding:UTF-8-*-
# 已经重写了 MysqlDao 的代码，将原来共用一个连接改为每执行一次建立一个连接，执行完成后即关闭
# 这个修改的原因是 MySQLdb 是非线程安全的，引擎执行过程中会用到多线程，由此导致了SQL不断的报错
# 引擎执行并非短时间的，长的会有几个小时，会导致SQL超时，数据库的配置不如代码的修改
# author: jingwu
import sys
import MySQLdb
#使用全新的配置文件
from engine.engineConfig import *

from engine.logger import scanLogger as logger

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
            self.module = self.__class__.__name__
        except Exception, e:
            logger.exception(e)

    def _connect(self):
        try:
            conn = MySQLdb.connect(self.host, self.user, self.passwd, db = self.database, charset = "utf8")
            cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        except Exception, e:
            logger.exception(e)
            return (False, None, None)
        return (True, conn, cursor)

    def _close(self, conn, cursor):
        try:
            cursor.close()
            conn.close()
        except Exception, e:
            logger.exception(e)
            return False

    #获取资产管理扫描任务ID
    def getAssetTaskId(self, taskId):
	retu = False
        try:
	    result, conn, cursor = self._connect()
            if result:
                sql = "select `asset_task_id` from `task` where `id` = '%s'" % (taskId)
                resultExec = cursor.execute(sql)
                res = cursor.fetchone()
                if res and len(res) > 0:
                    retu = res['asset_task_id']
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    def getDataBySql(self, sql):
        retu = []
        try:
	    result, conn, cursor = self._connect()
	    retu = []
            if result:
                resultExec = cursor.execute(sql)
                res = cursor.fetchall()
                if res and len(res) > 0:
                    retu = res
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    def getRowDataBySql(self, sql):
        retu = None
        try:
	    result, conn, cursor = self._connect()
            if result:
                resultExec = cursor.execute(sql)
                res = cursor.fetchone()
                if res and len(res) > 0:
                    retu = res
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    #根据任务ID获取扫描任务数据
    def getTaskData(self, taskId, columns = '*'):
	retu = None
        try:
	    result, conn, cursor = self._connect()
            if result:
                sql = "select %s from task where id = %s" % (columns, taskId)
                resultExec = cursor.execute(sql)
                res = cursor.fetchone()
                if res and len(res) > 0:
                    retu = res
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    #获取扫描站点配置
    def getSiteData(self, siteId, columns = '*'):
	retu = None
        try:
	    result, conn, cursor = self._connect()
            if result:
                sql = "select * from sites where id = '%s'" % (siteId)
                resultExec = cursor.execute(sql)
                res = cursor.fetchone()
                if res and len(res) > 0:
                    retu = res
            self._close(conn, cursor)
	    return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
	    return retu

    def getData(self, tablename, where, columns = '*'):
	retu = []
        try:
	    result, conn, cursor = self._connect()
            if result:
                whereSql = ' 1 = 1 '
                values = []
                for k in where:
                    whereSql = "%s and `%s` = %s" % (whereSql, k, '%s')
                    values.append(where[k])

                sql = "select %s from %s where %s" % (columns, tablename, whereSql)
                resultExec = cursor.execute(sql, tuple(values))
                res = cursor.fetchall()
                if res and len(res) > 0:
                    retu = res
            self._close(conn, cursor)
	    return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
	    return retu

    def getRowData(self, tablename, where, columns = '*'):
	retu = None
        try:
	    result, conn, cursor = self._connect()
            if result:
                whereSql = ' 1 = 1 '
                values = []
                for k in where:
                    whereSql = "%s and `%s` = %s" % (whereSql, k, '%s')
                    values.append(where[k])
                sql = "select %s from %s where %s" % (columns, tablename, whereSql)
                resultExec = cursor.execute(sql, tuple(values))
                res = cursor.fetchone()
                if res and len(res) > 0:
                    retu = res
            self._close(conn, cursor)
	    return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
	    return retu

    def updateHostWebScanState(self, taskId, assetTaskId, ip):
	retu = False
        try:
	    result, conn, cursor = self._connect()
            if result:
                sql = "update host_infos set `web_scan_state` = '1' where (select count(id) from sites where `state` <> '1' and `ip` = '%s' and task_id = '%s' and `asset_task_id` = '%s') = 0 and `ip` = '%s' and task_id = '%s' and `asset_task_id` = '%s'" % (ip, taskId, assetTaskId, ip, taskId, assetTaskId)
                resultExec = cursor.execute(sql)
                conn.commit()
	        retu = True
            self._close(conn, cursor)
	    return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
	    return retu

    def getSiteExceptionCount(self, siteId):
	retu = 0
        try:
	    result, conn, cursor = self._connect()
            if result:
                sql = "select `exception_count` from sites where id = '%s'" % (siteId)
                resultExec = cursor.execute(sql)
                res = cursor.fetchone()
                if res and res.has_key('exception_count'):
                    retu = res['exception_count']
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    #更新数据库信息
    def updateData(self, tablename, data, where):
	retu = False
        try:
	    result, conn, cursor = self._connect()
            if result:
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
                resultExec = cursor.execute(sql, tuple(values))
                conn.commit()
                retu = True
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    def deleteData(self, tablename, where):
	retu = False
        try:
	    result, conn, cursor = self._connect()
            if result:
                values = []
                whereSql = ''
                for k in where:
                    if whereSql == '':
                        whereSql = "`%s` = %s" % (k, '%s')
                    else:
                        whereSql = "%s and `%s` = %s" % (whereSql, k, '%s')
                    values.append(where[k])

                sql = "delete from %s where %s" % (tablename, whereSql)
                resultExec = cursor.execute(sql, tuple(values))
                conn.commit()
		retu = True

            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    #获取数据记录数
    def getDataCount(self, tablename, where):
        retu = 0
        try:
	    result, conn, cursor = self._connect()
            if result:
                whereSql = ''
                for k in where:
                    if whereSql == '':
                        whereSql = "`%s` = '%s'" % (k, where[k])
                    else:
                        whereSql = "%s and `%s` = '%s'" % (whereSql, k, where[k])

                sql = "select count(id) as c from %s where %s" % (tablename, whereSql)
                returnExec = cursor.execute(sql)
                res = cursor.fetchone()
                if res and len(res):
                    retu = res['c']
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    #获取抓取的URL数量
    def getSpiderUrlCount(self, siteId = 0, url = '', params = '', method = ''):
        retu = 0
        try:
	    result, conn, cursor = self._connect()
            if result:
                sql = "select count(id) as c from spider_url where `site_id`=%s and `url`=%s and `params`=%s and `method`=%s"
                sequence = (siteId, url, params, method)
                resultExec = cursor.execute(sql, sequence)
                res = cursor.fetchone()
                if res and len(res):
                    retu = res['c']
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    #获取抓取的URL数量
    def getSpiderUrlOtherCount(self, siteId = 0, url = '', params = '', method = ''):
        retu = 0
        try:
	    result, conn, cursor = self._connect()
            if result:
                sql = "select count(id) as c from spider_url_other where `site_id`=%s and `url`=%s and `params`=%s and `method`=%s"
                sequence = (siteId, url, params, method)
                resultExec = cursor.execute(sql, sequence)
                res = cursor.fetchone()
                if res and len(res):
                    retu = res['c']
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    def countSpiderUrlForGet(self, siteId, url, patternQuery):
        retu = 0
        try:
	    result, conn, cursor = self._connect()
            if result:
                sql = "select count(1) as total from spider_url where `site_id`=%s and `url`=%s and `pattern_query`=%s and `method`=%s"
                sequence = (siteId, url, patternQuery, "get")
                resultExec = cursor.execute(sql, sequence)
                res = cursor.fetchone()
                if res and len(res):
                    retu = res['total']
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    def countSpiderUrlForPost(self, siteId, url, patternPost):
        retu = 0
        try:
	    result, conn, cursor = self._connect()
            if result:
                sql = "select count(1) as total from spider_url where `site_id`=%s and `url`=%s and `pattern_post`=%s and `method`=%s"
                sequence = (siteId, url, patternPost, "post")
                resultExec = cursor.execute(sql, sequence)
                res = cursor.fetchone()
                if res and len(res):
                    retu = res['total']
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    #插入数据
    def insertData(self, tablename, data):
	retu = 0
        try:
	    result, conn, cursor = self._connect()
            if result:
                columns = []
                values = []
                valuesTuple = []

                for key in data:
                    columns.append('`' + key + '`')
                    values.append('%s')
                    valuesTuple.append(data[key])

                sql = "insert into %s (%s) values (%s)" % (tablename, ",".join(columns), ",".join(values))
                resultExec = cursor.execute(sql, tuple(valuesTuple))
                conn.commit()

                sql = "select LAST_INSERT_ID() as id"
                resultExec = cursor.execute(sql)
                conn.commit()
                res = cursor.fetchone()
                if res and len(res) > 0 and res['id'] > 0:
                    retu = res['id']

            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    def getUnscandSite(self, taskId, assetTaskId = 0):
	siteIds = []
        try:
	    result, conn, cursor = self._connect()
            if result:
                sql = "select `id` from `sites` where `state` <> '1' and `task_id` = '%s' and `asset_task_id` = '%s'" % (taskId, assetTaskId)
                resultExec = cursor.execute(sql)
                conn.commit()
                res = cursor.fetchall()
                if res and len(res) > 0:
                    for row in res:
                        siteIds.append(str(row['id']))

            self._close(conn, cursor)
            return siteIds
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return siteIds

    def getWebVulByPolicy(self, policyId):
        vulList = []
        try:
	    result, conn, cursor = self._connect()
            if result:
                vulList = []
                sql = "select `vul_id`,`level`,`vul_name`,`scan_type`,`script` from `web_vul_list` where web_vul_list.enable=1 and `vul_id` in (select `vul_id` from `web_vul_policy_ref` where `policy_id` = '%s') order by `priority` asc" % (str(policyId))
                resultExec = cursor.execute(sql)
                res = cursor.fetchall()
                if res and len(res) > 0:
                    for row in res:
                        vulList.append(row)
            self._close(conn, cursor)
            return vulList
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return vulList

    def getUrlList(self, siteId):
	retu = []
        try:
	    result, conn, cursor = self._connect()
            if result:
                sql = "select * from spider_url where site_id = '%s'" % (siteId)
                resultExec = cursor.execute(sql)
                res = cursor.fetchall()
                if res and len(res) > 0:
                    retu = res
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return retu

    def cleanWebScan(self, taskId, assetTaskId):
	retu = False
        try:
	    result, conn, cursor = self._connect()
            if result:
                #清空扫描任务字段
                sql = "update `task` set `web_scan_state` = '0', `web_search_site_state` = '0' where `id` = '%s' " % (taskId)
                resultExec = cursor.execute(sql)
                
                #清空扫描域名记录
                if assetTaskId > 0:
                    sql = "delete from `sites` where `task_id` = '%s' and `asset_task_id` = '%s'" % (taskId, assetTaskId)
                else:
                    sql = "delete from `sites` where `task_id` = '%s'" % (taskId)
                resultExec = cursor.execute(sql)
                
                #清空Web扫描结果
                if assetTaskId > 0:
                    sql = "delete from `web_result` where `task_id` = '%s' and `asset_task_id` = '%s'" % (taskId, assetTaskId)
                else:
                    sql = "delete from `web_result` where `task_id` = '%s'" % (taskId)
                resultExec = cursor.execute(sql)

                #清空Web扫描报文记录
                if assetTaskId > 0:
                    sql = "delete from `web_result_data` where `task_id` = '%s' and `asset_task_id` = '%s'" % (taskId, assetTaskId)
                else:
                    sql = "delete from `web_result_data` where `task_id` = '%s'" % (taskId)
                resultExec = cursor.execute(sql)
                
                # #清空扫描的URL记录结果
                # if assetTaskId > 0:
                #     sql = "delete from `spider_url` where `task_id` = '%s' and `asset_scan_id` = '%s'" % (taskId, assetTaskId)
                # else:
                #     sql = "delete from `spider_url` where `task_id` = '%s'" % (taskId)
                # resultExec = cursor.execute(sql)
                conn.commit()
		retu = True
            self._close(conn, cursor)
            return retu
        except Exception, e:
            self._close(conn, cursor)
            logger.exception(e)
            return False

mysqlDao = MysqlDao()

if __name__ == '__main__':
    print 'mysql connect error'

