#!/usr/bin/python
#-*-encoding:UTF-8-*-
import sys
import os
import atexit
import thread
import threading
import time
from Queue import Queue
import getopt
from engine_utils.common import *
from db.MysqlDao import *
from engineConfig import SCANER_TEMP_DIR

from logger import scanLogger as logger

class PortScanThread(threading.Thread):
    def __init__(self, target, taskId, assetTaskId, ports, timeout):
        try:
            threading.Thread.__init__(self)
            self.module = self.__class__.__name__
            self.target = target
            self.taskId = taskId
            self.assetTaskId = assetTaskId
            self.ports = ports
            self.timeout = timeout
            self.dao = MysqlDao()
        except Exception, e:
            logger.error(e)
        #end try
    #end def

    def getOs(self, ip, timeout):
        msg_dict = dict()
        msg_dict['flag'] = False
        msg_dict['os'] = ''
        msg_dict['runningos'] = ''
        msg_dict['osversion'] = ''
        msg_dict['macaddress'] = ''
        msg_dict['motherboard'] = ''
        msg_dict['devicetype'] = ''
        msg_dict['networkdistance'] = ''
        try:
            cmd = "nmap -O %s -P0 --host_scan-timeout %ss " % (ip, str(timeout))
            lines = popen(cmd)
            
            if lines and len(lines) > 0:
                for row in lines:
                    row = row.replace("\n","")
                    if row.find("Device type") >= 0 and row.find(":") >= 0:
                        temp = row.split(":")
                        if len(temp) >= 2:
                            msg_dict['devicetype'] = temp[1].strip()
                        #end if
                    #end if
                    if row.find("Running") >= 0 and row.find(":") >= 0:
                        temp = row.split(":")
                        if len(temp) >= 2:
                            msg_dict['runningos'] = temp[1].strip()
                        #end if
                    #end if
                    if row.find("OS details") >= 0 or row.find("Aggressive OS guesses") >= 0:
                        temp = row.split(":")
                        if len(temp) >= 2:
                            msg_dict['os'] = temp[1].strip()
                            msg_dict['osversion'] = msg_dict['os']                            
                        #end if
                    #end if
                    if row.find("MAC Address") >= 0 and row.find(":") >= 0:
                        temp = row.split(":")
                        if len(temp) >= 4:
                            msg_dict['macaddress'] = ":".join(row.split(":")[1:]).strip()
                        #end if
                    #end if
                    if row.find("Network Distance") >= 0 and row.find(":") >= 0:
                        temp = row.split(":")
                        if len(temp) >= 2:
                            msg_dict['networkdistance'] = row.split(":")[1].strip()
                        #end if
                    #end if
                #end for
                msg_dict['flag'] = True
            #end if
            return msg_dict
        except Exception, e:
            logger.error(e)
            return msg_dict
        #end try
    #end def
    
    def getUdpPorts(self, ip, ports, timeout):
        port_list = []
        try:
            cmd = "nmap -sU %s -p %s -P0 --host_scan-timeout %ss " % (ip, str(ports), str(timeout))
            lines = popen(cmd)
            state_num = 0
            service_num = 0
            if lines and len(lines) > 0:
                for row in lines:
                    row = row.replace("\n","")
                    if row.find("PORT") >= 0 and row.find("STATE") >= 0 and row.find("SERVICE") >= 0:
                        state_num = row.find("STATE")
                        service_num = row.find("SERVICE")
                    #end if
                    if row.find("/udp") >= 0 and row.find("closed") < 0:
                        port_dict = dict()
                        port_dict['port'] = row.split("/")[0]
                        port_dict['proto'] = "udp"
                        if service_num > len(row):
                            port_dict['state'] = row[state_num:].strip()
                        else:
                            port_dict['state'] = row[state_num:service_num - 1].strip()
                        #end if
                        if service_num > len(row):
                            port_dict['service'] = ""
                        else:
                            port_dict['service'] = row[service_num:].strip()
                        #end if
                        port_dict['version'] = ''
                        port_list.append(port_dict)
                    #end if
                #end for
            #end if
            
            return port_list
        except Exception, e:
            logger.error(e)
            return port_list
        #end try
    #end def
    
    def getPorts(self, ip, ports, timeout):
        port_list = []
        try:
            cmd = "nmap -sV %s -p %s -P0 --host_scan-timeout %ss " % (ip, str(ports), str(timeout))
            lines = popen(cmd)
            state_num = 0
            service_num = 0
            version_num = 0
            if lines and len(lines) > 0:
                for row in lines:
                    row = row.replace("\n","")
                    if row.find("PORT") >= 0 and row.find("STATE") >= 0 and row.find("SERVICE") >= 0 and row.find("VERSION") >= 0:
                        state_num = row.find("STATE")
                        service_num = row.find("SERVICE")
                        version_num = row.find("VERSION")
                    #end if
                    
                    if row.find("/tcp") >= 0 and row.find("closed") < 0:
                        port_dict = dict()
                        port_dict['port'] = row.split("/")[0]
                        port_dict['proto'] = "tcp"
                        if service_num > len(row):
                            port_dict['state'] = row[state_num:].strip()
                        else:
                            port_dict['state'] = row[state_num:service_num - 1].strip()
                        #end if
                        if service_num > len(row):
                            port_dict['service'] = ""
                        else:
                            if version_num > len(row):
                                port_dict['service'] = row[service_num:].strip()
                            else:
                                port_dict['service'] = row[service_num:version_num - 1].strip()
                            #end if
                        #end if
                        
                        if version_num > len(row):
                            port_dict['version'] = ""
                        else:
                            port_dict['version'] = row[version_num:].strip()
                        #end if
                        
                        port_list.append(port_dict)
                    #end if
                #end for
            #end if
            
            return port_list
        except Exception,e:
            logger.error(e)
            return port_list
        #end try
    #end def

    def run(self):
        try:
            while True:
                if self.target.qsize() < 1:
                    break
                #end if
                ip = self.target.get_nowait()
                if not ip or ip == "":
                    break
                #end if
                
                os_msg = self.getOs(ip, 60)
                update = {'mother_board':os_msg['motherboard'],'device_type':os_msg['devicetype'],'net_distance':os_msg['networkdistance'],'mac_address':os_msg['macaddress'],'os':os_msg['os']}
                self.dao.updateData('host_infos', update, {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip})
                
                port_msg = self.getPorts(ip, self.ports, self.timeout)
                if port_msg and len(port_msg) > 0:
                    for port_item in port_msg:
                        port = port_item['port']
                        proto = port_item['proto']
                        state = port_item['state']
                        service = port_item['service']
                        version = port_item['version']
                        
                        if self.dao.getDataCount('host_ports', {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'port':port}) > 0:
                            update = {'proto':proto,'state':state,'service':service,'version':version}
                            where = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'port':port}
                            self.dao.updateData('host_ports', update, where)
                        else:
                            insert = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'port':port,'proto':proto,'state':state,'service':service,'version':version}
                            self.dao.insertData('host_ports', insert)
                        #end if
                    #end for
                #end if
                
                upd_port_msg = self.getUdpPorts(ip, self.ports, self.timeout)
                if upd_port_msg and len(upd_port_msg) > 0:
                    for port_item in upd_port_msg:
                        port = port_item['port']
                        proto = port_item['proto']
                        state = port_item['state']
                        service = port_item['service']
                        version = port_item['version']
                        
                        if self.dao.getDataCount('host_ports', {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'port':port}) > 0:
                            update = {'proto':proto,'state':state,'service':service,'version':version}
                            where = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'port':port}
                            self.dao.updateData('host_ports', update, where)
                        else:
                            insert = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'port':port,'proto':proto,'state':state,'service':service,'version':version}
                            self.dao.insertData('host_ports', insert)
                        #end if
                    #end for
                #end if
                
                self.dao.updateData('host_infos', {'port_scan_state':1}, {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip})
            
            #end while
        except Exception,e:
            logger.error(e)
        #end try
    #end def
#end class

class PortScanEngine:
    def __init__(self, taskId, action):
        self.taskId = str(taskId)
        self.action = action
        self.module = self.__class__.__name__
        self.assetTaskId = 0
        self.dao = MysqlDao()
        self.target = Queue()
        self.thread = 1
        self.timeout = 30
        self.ports = '80,81,8081,8089,443,22,23,3306,3389'

        #任务配置
        self.taskCnf = {}

        #线程锁
        self.threadLock = threading.Lock()

        if self.checkProgress() == False:
            sys.exit(3)
        #end if
    #end def

    #判断进程文件是否存在
    def checkProgress(self):
        try:
            pid = "%sPortScanEngine-%s" % (SCANER_TEMP_DIR, self.taskId)
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
            if self.action == 'restart':
                logger.debug('restart to scan port')
                self.dao.deleteData('host_ports', {'task_id':self.taskId,'asset_task_id':self.assetTaskId})
                self.dao.updateData('host_infos', {'port_scan_state':0}, {'task_id':self.taskId,'asset_task_id':self.assetTaskId})
                self.dao.updateData('task', {'port_scan_state':0}, {'id':self.taskId})
            #end if

            self.taskCnf = self.dao.getTaskData(self.taskId)
            if self.taskCnf == False:
                return False
            #end if
            logger.debug('get task config success')
            self.assetTaskId = self.taskCnf['asset_task_id']
            self.thread = self.taskCnf['port_scan_thread']
            self.timeout = self.taskCnf['port_scan_timeout']
            self.policy = self.taskCnf['port_scan_policy']

            res = self.dao.getRowData('port_scan_policy', {'id':self.policy})
            if res and len(res) > 0:
                self.ports = res['ports']
                logger.debug('get port scan policy success')
            #end if

            if self.taskCnf['port_scan_enable'] == 1 and self.taskCnf['port_scan_state'] == 0:
                logger.debug('port scan init success')
                return True
            #end if

            logger.debug('port scan is finished')
            self.dao.updateData('host_infos', {'port_scan_state':1}, {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'state':1})

            return False
        except Exception,e:
            logger.error(e)
            return False
        #end try    
    #end def

    def finish(self):
        try:
            currentTime = time.strftime("%Y-%m-%d %X",time.localtime())
            
            if self.dao.getDataCount('host_infos', {'state':1,'port_scan_state':0,'task_id':self.taskId,'asset_task_id':self.assetTaskId}) == 0:
                self.dao.updateData('task', {'port_scan_state':1}, {'id':self.taskId})
            #end if
            
            self.dao.updateData('task', {'state':3, 'end_time':currentTime}, {'id':self.taskId,'init_state':1,'prescan_state':1,'host_scan_state':1,'web_scan_state':1,'weak_pwd_scan_state':1})
            
            #sendEmail(self.taskId)
        except Exception,e:
            logger.error(e)
        #end try  
    #end def

    def run(self):
        try:
            if self.init():
                while True:
                    taskCnf = self.dao.getTaskData(self.taskId)
                    prescanState = taskCnf['prescan_state']

                    ret = self.dao.getData('host_infos', {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'state':1,'port_scan_state':0})
                    if ret and len(ret) > 0:
                        for row in ret:
                            self.target.put(row['ip'])
                        #end for
                        if self.target.qsize() > 0:
                            list = []
                    
                            i = 0
                            for i in range(self.thread):
                                temp = PortScanThread(self.target, self.taskId, self.assetTaskId, self.ports, self.timeout)
                                list.append(temp)
                            #end for
                    
                            i = 0
                            for i in range(len(list)):
                                list[i].start()
                            #end for
                    
                            i = 0
                            for i in range(len(list)):
                                list[i].join()
                            #end for
                        #end if
                    #end if
                    if prescanState == 1:
                        break
                    else:
                        time.sleep(5)
                        continue
                    #end if
                #end while
            #end if
            self.finish()
        except Exception,e:
            logger.error(e)
            self.finish()
        #end try
    #end if
#end class

def Usage():
    print os.path.split(__file__)[1] + ' usage:'
    print '-h,--help: print help message.'
    print '-v, --version: print script version'
    print '-t, --task: input scan task id'
    print '-a, --action: input scan task action'
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

    #检查扫描方式参数
    if action == '':
        action = 'start'
    #end if
    if action not in ['start', 'restart']:
        print '-a, --action argv error'
        sys.exit(3)
    #end if

    portScanEngine = PortScanEngine(taskId, action)
    portScanEngine.run()
#end def

if __name__ == '__main__':
    main(sys.argv)
    exit()
#end if
