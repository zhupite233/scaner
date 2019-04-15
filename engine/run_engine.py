#!/usr/bin/python
#-*-encoding:UTF-8-*-
from ScanSite import *
from SearchSite import *
import sys, getopt
import setproctitle
import commands
from engineConfig import SCANER_TEMP_DIR

from logger import scanLogger as logger

class WebScanEngine:
    def __init__(self, taskId, action):
        self.taskId = str(taskId)
        self.action = action
        self.module = self.__class__.__name__
        self.assetTaskId = 0
        self.dao = MysqlDao()

           #任务配置
        self.taskCnf = {}

           #线程锁
        self.threadLock = threading.Lock()

        if self.checkProgress() == False:
            sys.exit(3)

    #判断进程文件是否存在
    def checkProgress(self):
        try:
            command = "ps -ef | grep -v grep | grep engine-task-" + str(self.taskId) + " | wc -l"
            output = commands.getoutput(command)
            if output > 0:
                #return False
                pass

            pid = "%sWebScanEngine-%s" % (SCANER_TEMP_DIR, self.taskId)
            if os.path.exists(pid):
                return False

            return True
        except Exception, e:
            logger.error(e)
            return False

    #初始化Web扫描
    def init(self):
        try:
            self.taskCnf = self.dao.getTaskData(self.taskId)
            if self.taskCnf == False:
                return False
            self.assetTaskId = self.taskCnf['asset_task_id']

            self.taskCnf['vulDict'] = {}
            self.taskCnf['vulList'] = []
            vulList = self.dao.getWebVulByPolicy(self.taskCnf['web_scan_policy'])
            for row in vulList:
                vulId = str(row['vul_id'])
                self.taskCnf['vulDict'][vulId] = row
                self.taskCnf['vulList'].append(vulId)

            return True
        except Exception, e:
            logger.debug(e)
            return False

    #清除上一次Web扫描
    def clean(self):
        try:
            return self.dao.cleanWebScan(self.taskId, self.assetTaskId)
        except Exception, e:
            logger.error(e)
            return False

    #开始执行Web扫描
    def run(self):
        try:
            logger.debug('clear last scan')
            if self.action == 'restart':
                if self.clean() == False:
                    logger.error('清空上一次扫描失败')
                    return False

            logger.debug('init scan config')
            #初始化扫描任务
            if self.init() == False:
                logger.error('初始化扫描信息失败')
                return False

            logger.debug('check init state')
            if self.taskCnf['init_state'] == 0:
                logger.error('初始化失败')
                return False

            logger.debug('check if need to scan web vul')
            if self.taskCnf['web_scan_enable'] == 0:
                logger.debug('不需要扫描Web漏洞')
                self.finish()
                return True

            logger.debug('check web scan is finished')
            if self.taskCnf['web_scan_state'] == 1:
                logger.debug('Web扫描已完成')
                return True

            #调用获取域名的线程和扫描域名的线程
            threadList = []
            threadList.append(SearchSite(self.taskId, self.taskCnf))
            for i in range(self.taskCnf['web_scan_thread']):
                threadList.append(ScanSite(self.taskId, self.assetTaskId, self.taskCnf, self.threadLock))
            for t in threadList:
                t.start()
            for t in threadList:
                t.join()

            self.finish()

        except Exception, e:
            logger.error(e)
            return False

    #完成Web扫描
    def finish(self):
        try:
            currentTime = time.strftime("%Y-%m-%d %X",time.localtime())

            #检查网站是否都已经扫描完成
            where = {'state': '0', 'task_id': self.taskId,'asset_task_id':self.assetTaskId}
            if self.dao.getDataCount('sites', where) > 0:
                return False
            #end if

            self.dao.updateData('task', {'web_scan_state': '1'}, {'id': self.taskId})

            #更新主机表的状态
            where = {'task_id': self.taskId, 'asset_task_id':self.assetTaskId}
            self.dao.updateData('host_infos', {'web_scan_state':1}, where)

            #更新扫描任务表
            update = {'state':'3', 'end_time':currentTime}
            where = {'id':self.taskId, 'init_state':'1', 'prescan_state':'1', 'port_scan_state':'1', 'host_scan_state':'1', 'web_scan_state':'1', 'weak_pwd_scan_state':'1'}
            self.dao.updateData('task', update, where)

            #清理Web扫描缓存目录
            #remove_web_tmp(self.taskId)

            #发送扫描完成邮件
            #sendEmail(self.taskId)

            #更新漏洞统计
            #updateTaskManage()

            #check_if_all_end(self.taskId)

            #更新资产管理漏洞统计
            #updateAssetCount(self.taskId,self.assetTaskId)

            return True
        except Exception, e:
            logger.error(e)
            return False

def Usage():
    print os.path.split(__file__)[1] + ' usage:'
    print 'scanEngine.py action [option]'
    print ''
    print 'help:    print help message.'
    print 'version: print script version'
    print 'start:   start task, the taskid is require'
    print '     -t, --task: input scan task id'
    print 'restart: restart task, the taskid is require'
    print '     -t, --task: input scan task id'

def Version():
    print os.path.split(__file__)[1] + ' 1.1.1'


def main(argv):
    #获取命令行参数
    if len(argv) < 2:
        Usage()
        sys.exit()

    #处理action
    action = argv[1]
    if action not in ['start', 'restart', 'help', 'version']:
        Usage()
        sys.exit()

    if action == "help":
        Usage()
        sys.exit()

    if action == "version":
        Version()
        sys.exit()

    if len(argv) < 3:
        Usage()
        sys.exit()

    try:
        opts, args = getopt.getopt(argv[2:], 't:', ['task='])
    except getopt.GetoptError, err:
        logger.error(err)
        Usage()
        sys.exit(2)

    #识别参数
    taskId = '0'
    for k, v in opts:
        if k in ('-t', '--task'):
            taskId = v
        else:
            pass

    if not taskId or int(taskId) <1:
        print "--task is error"
        Usage()
        sys.exit(2)
    taskId = int(taskId)

    processname = "engine-task-" + str(taskId)
    setproctitle.setproctitle(processname)

    webScanEngine = WebScanEngine(taskId, 'restart')
    webScanEngine.run()

if __name__ == '__main__':
    main(sys.argv)
    exit()

