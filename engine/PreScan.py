#!/usr/bin/python
# -*- coding: utf-8 -*-
import getopt
from engine_lib import yd_json as json
from db.MysqlDao import *
from engine_utils.common import *
from engineConfig import SCANER_TEMP_DIR

from logger import scanLogger as logger

class PreScanThread(threading.Thread):
    def __init__(self, queue, taskId, assetTaskId):
        threading.Thread.__init__(self)
        self.module = self.__class__.__name__
        self.queue = queue
        self.taskId = str(taskId)
        self.assetTaskId = str(assetTaskId)
        self.dao = MysqlDao()

    def checkIp(self,ip):
        try:
            cmd = "nmap -sP %s --host_scan-timeout 60s" % (ip)
            lines = popen(cmd)
            for row in lines:
                if row.find('#') < 0:
                    if row.find('MAC Address') >= 0 or row.find("appears to be up") >= 0 or row.find("1 host_scan up") >= 0:
                        return True
                    #end if
                #end if
            #end for

            cmd = "nmap -Pn %s --host_scan-timeout 60s" % (ip)
            lines = popen(cmd)
            for row in lines:
                if row.find('#') < 0:
                    if row.find('/tcp') > 0 and row.find('open') > 0:
                        return True
                    #end if
                #end if
            #end for
            
            cmd = "nmap -sS %s -p 21,23,25,80,135,139,445,2121,3389,3306,1433,7777,2433,5631,4899,5800,5900,8000,8080,16433 --host_scan-timeout 30s -P0" % (ip)
            lines = popen(cmd)
            for row in lines:
                if (row.find('/tcp') > 0 and row.find('open') > 0) or row.find('MAC Address') >= 0:
                    return True
                #end if
            #end for
            
            return False
        except Exception, e:
            logger.error(e)
            return False
        #end try
    #end def
        
    def run(self):
        try:
            while True:
                if self.queue.qsize() < 1:
                    print "prescan thread exit"
                    break
                #end if
                ip = self.queue.get_nowait()
                
                if not ip or ip == "":
                    print "prescan thread exit"
                    break
                #end if
                
                if self.checkIp(ip):
                    self.dao.updateData('host_infos', {'state':1}, {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip})
                else:
                    logger.debug("ip is not alive: %s" % (ip))
                    self.dao.updateData('host_infos', {'state':2,'port_scan_state':1,'host_scan_state':1,'web_scan_state':1,'weak_pwd_scan_state':1}, {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip})
                #end if
            #end while
        except Exception,e:
            logger.error(e)
        #end try
    #end def
#end class


class PreScan:
    def __init__(self, taskId, action):
        self.module = self.__class__.__name__
        self.taskId = taskId
        self.action = action
        self.assetTaskId = 0
        self.queue = Queue()
        self.ipList = []
        self.dao = MysqlDao()

        if self.checkProgress() == False:
            sys.exit()
        #end if
    #end def

    #判断进程文件是否存在
    def checkProgress(self):
        try:
            pid = "%sPreScan-%s" % (SCANER_TEMP_DIR, self.taskId)
            if os.path.exists(pid):
                return False
            #end if

            return True
        except Exception, e:
            logger.error(e)
            return False
        #end try
    #end def
    
    def init(self):
        try:
            if self.action == 'reinit':
                logger.debug('start to reinit task')
                reinitDb = {'state':1,'init_state':0,'prescan_state':0,'web_scan_state':0,'weak_pwd_scan_state':0,'port_scan_state':0,'host_scan_state':0,'start_time':'0000-00-00 00:00:00','end_time':'0000-00-00 00:00:00'}
                self.dao.updateData('task', reinitDb, {'id':self.taskId})
            #end if

            currentTime = time.strftime("%Y-%m-%d %X",time.localtime())
            
            self.dao.updateData('task', {'state':2,'start_time':currentTime,'end_time':'0000-00-00 00:00:00'}, {'id':self.taskId,'state':1})

            self.dao.updateData('task', {'state':3,'end_time':currentTime}, {'id':self.taskId,'init_state':1,'prescan_state':1,'web_scan_state':1,'weak_pwd_scan_state':1,'port_scan_state':1,'host_scan_state':1})

            taskCnf = self.dao.getTaskData(self.taskId)
            self.assetTaskId = taskCnf['asset_task_id']

            if taskCnf['init_state'] == 1:
                return
            #end if
            
            target = taskCnf['target'].encode('utf8')
            if target == '':
                target = []
            else:
                target = json.read(target.encode('utf8'))
            #end if

            #clear host_infos
            self.dao.deleteData('host_infos', {'task_id':self.taskId,'asset_task_id':self.assetTaskId})

            #clear host_ports
            self.dao.deleteData('host_ports', {'task_id':self.taskId,'asset_task_id':self.assetTaskId})

            #clear sites
            self.dao.deleteData('sites', {'task_id':self.taskId,'asset_task_id':self.assetTaskId})

            #clear spider_url
            self.dao.deleteData('spider_url', {'task_id':self.taskId,'asset_task_id':self.assetTaskId})

            #clear web_result
            self.dao.deleteData('web_result', {'task_id':self.taskId,'asset_task_id':self.assetTaskId})

            #clear web_result_data
            self.dao.deleteData('web_result_data', {'task_id':self.taskId,'asset_task_id':self.assetTaskId})

            #clear host_result
            self.dao.deleteData('host_result', {'task_id':self.taskId,'asset_task_id':self.assetTaskId})

            #clear weak_pwd_result
            self.dao.deleteData('weak_pwd_result', {'task_id':self.taskId,'asset_task_id':self.assetTaskId})

            siteList = []
            ipList = []

            for item in target:
                try:
                    domain = ''
                    ip = ''

                    if item.has_key('domain'):
                        domain = item['domain']
                    #end if

                    if item.has_key('ip'):
                        ip = item['ip']
                    #end if

                    if domain == '' and ip == '':
                        continue
                    #end if

                    if ip == '':
                        ip = domainToip(domain)
                        if ip == False:
                            continue
                        #end if
                    #end if

                    ipDb = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip}
                    if ip not in ipList:
                        hostId = self.dao.insertData('host_infos', ipDb)
                        if hostId > 0:
                            ipList.append(ip)
                        #end if
                    #end if

                except Exception, e1:
                    logger.error(e1)
                #end try
            #end for

            self.dao.updateData('task', {'init_state':1}, {'id':self.taskId})
            
        except Exception,e:
            logger.error(e)
        #end try
    #end def
    
    def main(self):
        try:
            taskCnf = self.dao.getTaskData(self.taskId)
            self.assetTaskId = taskCnf['asset_task_id']
            
            if taskCnf['init_state'] == 0:
                return
            #end if

            if taskCnf['prescan_state'] == 1:
                return
            #end if

            ipWhere = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'state':0}
            ipList = self.dao.getData('host_infos', ipWhere, 'ip')

            if len(ipList) > 0:
                for row in ipList:
                    ip = row['ip'].encode('utf8')
                    self.queue.put(ip)
                #end for

                threadList = []
                for i in range(10):
                    temp = PreScanThread(self.queue, self.taskId, self.assetTaskId)
                    threadList.append(temp)
                #end for
                
                for i in range(len(threadList)):
                    threadList[i].start()
                #end for
                
                for i in range(len(threadList)):
                    threadList[i].join()
                #end for
            #end if

            self.dao.updateData('task', {'prescan_state':1}, {'id':self.taskId})
            
            currentTime = time.strftime("%Y-%m-%d %X",time.localtime())
            where = {'id':self.taskId,'init_state':1,'prescan_state':1,'port_scan_state':1,'host_scan_state':1,'web_scan_state':1,'weak_pwd_scan_state':1}
            update = {'state':3,'end_time':currentTime}
            self.dao.updateData('task', update, where)
            
        except Exception, e:
            logger.error(e)
        #end try    
    #end def

    def run(self):
        try:
            self.init()
            self.main()
        except Exception, e:
            logger.error(e)
        #end try
    #end def
#end class

def Usage():
    print os.path.split(__file__)[1] + ' usage:'
    print '-h,--help: print help message.'
    print '-v, --version: print script version'
    print '-t, --task: input scan task id'
    print '-a, --action: input scan task action, reinit'
#end def

def Version():
    print os.path.split(__file__)[1] + ' 1.1.1'
#end def

def main(argv):
    #获取命令行参数
    try:
        opts, args = getopt.getopt(argv[1:], 'hvt:a:', ['help', 'version' 'task=', 'action='])
    except getopt.GetoptError, err:
        logger.error(err)
        Usage()
        sys.exit(2)
    #end try

    #识别参数
    taskId = ''
    action = ''
    for k, v in opts:
        if k in ('-h', '--help'):
            Usage()
            sys.exit(1)
        elif k in ('-v', '--version'):
            Version()
            sys.exit(0)
        elif k in ('-t', '--task'):
            taskId = v
        elif k in ('-a', '--action'):
            action = v
        else:
            print 'unhandled option'
            sys.exit(3)
        #end def
    #end for

    #检查扫描任务ID参数
    if taskId == '' or taskId.isdigit() == False:
        print '-t, --task argv error'
    #end if

    if action != '' and action not in ['reinit']:
        print '-a, --action argv error'
        sys.exit(3)
    #end if

    prescan = PreScan(taskId, action)
    prescan.run()
#end def

if __name__ == '__main__':
    main(sys.argv)
    exit()
#end if


