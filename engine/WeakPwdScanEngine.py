#!/usr/bin/env python
# -*- coding: utf-8 -*-
from Queue import Queue
import threading
from  threading import Thread
import urllib2
import time
import socket
import commands
import os
import sys
import base64
import re
import sys
import telnetlib
import getopt
from telnetlib import Telnet
from pexpect import *
from engine_utils.common import *
from db.MysqlDao import *
from engineConfig import SCANER_TEMP_DIR

from logger import scanLogger as logger

class Telnet_login:
    def __init__(self, host, port=23):
        self.host = host;
        self.port = port
        self.timeout = 20
        self.prompt = "\w+:"
        self.errmsg = ""

        self.geterrormsg()
        self.err_dict = ['incorrect','retry','error','failed','fail']
        self.suc_dict = ['welcome', 'success']
    #end def

    def connect(self):
        return Telnet(self.host,self.port)
    #end def

    def geterrormsg(self):
        try:
            errUser = 'null111'
            errPass = 'n1l1u1l'
            errfp = self.connect()
            errfp.set_debuglevel(1)
            _, _, banner = errfp.expect([self.prompt], timeout=self.timeout)
            errfp.write(errUser+'\r\n')
            _, _, passwdinfo = errfp.expect([self.prompt], timeout=self.timeout)
            errfp.write(errPass+'\r\n')
            _, _, self.errmsg = errfp.expect([self.prompt,'#','\$'], timeout=self.timeout)
            self.errmsg = self.errmsg.replace(errUser,'').replace('*'*len(errPass),'').strip()
            errfp.close()
        except Exception:
            self.errmsg = ""
        #end try
    #end def


    def check(self,User,Passwd):
        try:
            loginfp = self.connect()
            loginfp.set_debuglevel(1)
            _, _, banner = loginfp.expect([self.prompt], timeout=self.timeout)
            loginfp.write(User+'\r')
            _, _, passwdinfo = loginfp.expect([self.prompt], timeout=self.timeout)
            if passwdinfo.replace(User,'').strip() == self.errmsg:
                return False
            #end if
            loginfp.write(Passwd+'\r')
            login_index, _, loginmsg = loginfp.expect([self.prompt,'#','\$'], timeout=self.timeout)
            loginmsg = loginmsg.replace(User,'').strip()
            loginfp.close()
            for item in self.err_dict:
                if item in  loginmsg.lower():
                    return False
                #end if
            #end for
            for suc in self.suc_dict:
                if suc in loginmsg.lower():
                    return True
                #end if
            #end for
            if self.errmsg != '' and loginmsg != self.errmsg:
                return True
            else:
                return False
            #end if
        except Exception, e:
            return False
        #end try
    #end def
#end class

class WeakPwdScanEngine:
    def __init__(self, taskId, action):
        self.taskId = str(taskId)
        self.action = action
        self.module = self.__class__.__name__
        self.assetTaskId = 0
        self.dao = MysqlDao()
        self.thread = 1
        self.timeout = 30
        self.policy = []
        self.portDic = {'21':'ftp','22':'ssh','3389':'rdp','23':'telnet','1433':'mssql','3306':'mysql','1521':'oracle','445':'smb','139':'smb','5900':'vnc'}
        #self.compiledRule = re.compile('\x5b[\d]+\x5d\x5b[\w]+\x5d\s+host_scan:.*.login:.*.password:.*.')
        self.compiledRule = re.compile('\[([0-9]+)\]\[([0-9a-zA-Z]+)\]\s+host_scan:\s+([0-9\.]+)\s+login:\s+(.*)\s+password:\s+(.*)')
        #[3306][mysql] host_scan: 127.0.0.1   login: root   password: 123456

        #任务配置
        self.taskCnf = {}

        self.target = Queue()
        #线程锁
        self.threadLock = threading.Lock()

        if self.checkProgress() == False:
            sys.exit(3)
        #end if
    #end def

    #判断进程文件是否存在
    def checkProgress(self):
        try:
            pid = "%sWeakPwdScanEngine-%s" % (SCANER_TEMP_DIR, self.taskId)
            if os.path.exists(pid):
                return False
            #end if

            return True
        except Exception, e:
            logger.error(e)
            return False
        #end try
    #end def

    #初始化Web扫描
    def init(self):
        try:
            if self.action == 'restart':
                logger.debug('restart to scan weak pwd')
                self.dao.deleteData('weak_pwd_result', {'task_id':self.taskId,'asset_task_id':self.assetTaskId})
                self.dao.updateData('host_infos', {'weak_pwd_scan_state':0}, {'task_id':self.taskId,'asset_task_id':self.assetTaskId})
                self.dao.updateData('task', {'weak_pwd_scan_state':0}, {'id':self.taskId})
            #end if
            self.taskCnf = self.dao.getTaskData(self.taskId)
            if self.taskCnf == False:
                return False
            #end if
            self.assetTaskId = self.taskCnf['asset_task_id']
            self.thread = self.taskCnf['weak_pwd_scan_thread']
            self.timeout = self.taskCnf['weak_pwd_scan_timeout']
            self.policy = self.taskCnf['weak_pwd_scan_policy'].split(',')


            return True
        except Exception, e:
            logger.error(e)
            return False
        #end try
    #end def

    def finish(self):
        try:
            currentTime = time.strftime("%Y-%m-%d %X",time.localtime())
            
            if self.dao.getDataCount('host_infos', {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'state':1,'weak_pwd_scan_state':0}) == 0:
                self.dao.updateData('task', {'weak_pwd_scan_state':1}, {'id':self.taskId})
            #end if
            
            self.dao.updateData('task', {'state':3, 'end_time':currentTime}, {'id':self.taskId,'init_state':1,'prescan_state':1,'host_scan_state':1,'web_scan_state':1,'weak_pwd_scan_state':1})
            
            #sendEmail(self.taskId)

        except Exception, e:
            logger.error(e)
        #end try
    #end if

    def checkIpPort(self,ip):
        try:
            res = []            
            portList = []
            cmd = ''
            if '1' in self.policy:
                portList.append('21')
            #end if
            if '2' in self.policy:
                portList.append('22')
            #end if
            if '3' in self.policy:
                portList.append('3389')
            #end if
            if '4' in self.policy:
                portList.append('23')
            #end if
            if '5' in self.policy:
                portList.append('1443')
            #end if
            if '6' in self.policy:
                portList.append('3306')
            #end if
            if '7' in self.policy:
                portList.append('1521')
            #end if
            if '8' in self.policy:
                portList.append('445')
                portList.append('139')
            #end if
            if '9' in self.policy:
                portList.append('5900')
            #end if

            if len(portList) > 0:
                cmd = "nmap -sS %s -p %s --host_scan-timeout 30s -P0" % (ip, ','.join(portList))
                #logger.debug(cmd)
                lines = popen(cmd)
                for row in lines:
                    if row.find('/tcp') > 0 and row.find('open') > 0:
                        port = row.split('/tcp')[0]
                        if cmp(port,'139') == 0 and ('smb' in res):
                            continue
                        #end if
                        res.append(self.portDic.get(port))
                    #end if
                #end for
                return res
            else:
                return []
            #end if
        except Exception, e:
            logger.error(e)
            return []
        #end try
    #end def

    def updateResult(self, ip, vulName, username, password):
        try:
            if vulName == "RDP":
                vulName = "远程协助"
            #end if
            
            if self.dao.getDataCount('weak_pwd_result', {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'vul_name':vulName,'username':username,'password':password}) > 0:
                return
            #end if

            insert = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'vul_name':vulName,'username':username,'password':password}
            self.dao.insertData('weak_pwd_result', insert)

        except Exception,e:
            logger.error(e)
        #end try
    #end def

    def crack(self, ip, type):
        try:
            logger.debug('start to crack ip: %s, vulName: %s' % (ip, type))
            dicFile = "dict/%s.dic" % (type)
            
            f = open(dicFile, "r")
            lines = f.readlines()
            
            startTime = time.time()
            if type == "telnet":
                telnet_check = Telnet_login(ip)
            #end if
            
            for line in lines:
                try:
                    if int(time.time() - startTime) > self.timeout:
                        break
                    #end if
                
                    if type == "vnc":
                        username = ""
                        password = line.strip()
                        password = password.replace("\\", "\\\\")
                        password = password.replace("`", "\\`")
                        password = password.replace("\"", "\\\"")
                    else:
                        up = line.split(":", 1)
                        if len(up) < 2:
                            continue
                        #end if
                        username = up[0].strip()
                        password = up[1].strip()
                        username = username.replace("\\", "\\\\")
                        username = username.replace("`", "\\`")
                        username = username.replace("\"", "\\\"")
                        password = password.replace("\\", "\\\\")
                        password = password.replace("`", "\\`")
                        password = password.replace("\"", "\\\"")
                    #end if
                
                    cmd = ""
                    if type == "vnc":
                        if password == "{NULL}":
                            cmd = "hydra -t 1 -sid=%s -p \"\" %s %s" % (self.taskId, ip, type)
                        else:
                            cmd = "hydra -t 1 -sid=%s -p \"%s\" %s %s" % (self.taskId, password, ip, type)
                        #end if
                    elif type == "oracle":
                        if password == "{NULL}":
                            cmd = "hydra -t 1 -sid=%s -l \"%s\" -e n %s %s ORCL" % (self.taskId, username, ip, type)
                        else:
                            cmd = "hydra -t 1 -sid=%s -l \"%s\" -p \"%s\" %s %s ORCL" % (self.taskId, username, password, ip, type)
                        #end if
                    else:
                        if password == "{NULL}":
                            cmd = "hydra -t 1 -sid=%s -l \"%s\" -e n %s %s" % (self.taskId, username, ip, type)
                        else:
                            cmd = "hydra -t 1 -sid=%s -l \"%s\" -p \"%s\" %s %s" % (self.taskId, username, password, ip, type)
                        #end if
                    #end if
                    
                    logger.debug(cmd)
                    (output, exitstatus) = run(cmd, withexitstatus=1, timeout=20)
                    logger.debug(output)
                    #m = self.compiledRule.findall(output)
                    #print output
                    #print m
                    #if len(m) == 1:
                    if output.find('1 valid password found') > 0:
                        #v = m[0]
                        #username = v[3].strip()
                        #password = v[4].strip()

                        if type == "telnet":
                            telnet_passwd = '' if len(password) == 0 else password
                            if not telnet_check.check(username,telnet_passwd):
                                continue
                            #end if
                        #end if

                        if len(password) == 0:
                            self.updateResult(ip, type.upper(), username, "空密码")
                            
                            if type.upper() == "FTP":
                                self.updateResult(ip, type.upper(), "ftp", "ftp")
                            #end if
                        else:
                            self.updateResult(ip, type.upper(), username, password)
                        #end if
                        
                        return 

                    #end if
                except Exception, e1:
                    logger.error(e)
                    continue
                #end try
            #end for
        except Exception,e:
            logger.error(e)
        #end try
    #end def

    def updateHostState(self, ip):
        try:
            self.dao.updateData('host_infos', {'weak_pwd_scan_state':1}, {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip})
            self.dao.updateData('host_infos', {'end_time':''}, {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'port_scan_state':1,'host_scan_state':1,'web_scan_state':1,'weak_pwd_scan_state':1,'ip':ip})
        except Exception,e:
            logger.error(e)
        #end try
    #end def

    def scanMain(self):
        try:
            logger.debug('weak pwd scan main is start')
            while True:
                if self.target.qsize() < 1:
                    break
                #end if
                ip = self.target.get_nowait()
                if ip and ip != '':
                    logger.debug("weak pwd scan man is scaning ip: %s" % (ip))
                    scanList = self.checkIpPort(ip)
                    if scanList and len(scanList) > 0:
                        for line in scanList:
                            self.crack(ip, line)
                        #end for
                    #end if
                    #更新主机状态
                    self.updateHostState(ip)
                #end if
            #end while
        except Exception,e:
            logger.error(e)
        #end try
    #end def

    def run(self):
        try:
            if self.init() == False:
                return
            #end if
            
            if self.taskCnf['init_state'] == 0:
                return
            #end if

            if self.taskCnf['weak_pwd_scan_enable'] == 0:
                self.updateData('host_infos', {'weak_pwd_scan_state':1}, {'task_id':self.taskId, 'asset_task_id':self.assetTaskId,'state':1})
                self.finish()
            #end if

            res = self.dao.getData('host_infos', {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'weak_pwd_scan_state':0})
            if res and len(res) > 0:
                for row in res:
                    self.target.put(row['ip'])
                    self.dao.deleteData('weak_pwd_result', {'task_id':self.taskId,'asset_task_id':self.assetTaskId, 'ip':row['ip']})
                #end for
            #end if
            
            threadList = []
            for i in range(self.thread):
                threadList.append(Thread(target=self.scanMain, args=()))
            #end for
            for t in threadList:
                t.start()
            #end for
            for t in threadList:
                t.join()
            #end for
            
            self.finish()

            #clear oracle log
            os.system("rm -rf /root/oradiag_root")
            os.system("rm -rf /root/hydra.restore")
            os.system("rm -rf /oradiag_root")
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

    weakPwdScanEngine = WeakPwdScanEngine(taskId, action)
    weakPwdScanEngine.run()
#end def

if __name__ == '__main__':
    main(sys.argv)
    exit()
#end if

