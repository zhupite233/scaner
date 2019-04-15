#!/usr/bin/env python
#-*-encoding:UTF-8-*-
import os, subprocess, sys, time, threading, signal, fcntl
from Queue import *
from engine_utils.common import *
import socket
import urllib
import struct
import re
import getopt
from db.MysqlDao import *
from engineConfig import SCANER_TEMP_DIR
import base64
from logger import scanLogger as logger

NASL_DIR = "/naslscript/plugins/"
NASL_EXE = "/opt/nessus/bin/nessuscmd"


class ScriptScanThread(threading.Thread):
    
    def __init__(self, taskCnf, ip, vulIds):
        threading.Thread.__init__(self)
        self.module = self.__class__.__name__
        self.taskCnf = taskCnf
        self.taskId = taskCnf['id']
        self.assetTaskId = taskCnf['asset_task_id']
        self.vulIds = vulIds
        self.ip = ip
        self.dao = MysqlDao()

    def func(m):
        try:
            tmp = re.sub(r"\s", "", m.group(1)).strip()
            return "".join(base64.decodestring(tmp).split("\n"))
        except Exception, e:
            raise

    def outputDecode(self, data):
        try:
            p = re.compile("#YB64#([\s\S]*?)#YB64#")
            return p.sub(self.func, data)
        except Exception, e:
            logger.error(e)
            return ''
        #end try
    #end def

    def handleResult(self, popen_data):
        try:
            return_result = []
            datalist = []
            for l in popen_data:
                if l.split():
                    datalist.append(l.strip())
                #end if
            #end for
            
            data = "\n".join(datalist)
            data = data.replace("\n|", "\n")

            datalist = data.split("\n-")
            datalist.pop(0)

            tmp = []
            p = re.compile(r'\n{2,}')
            
            for i in datalist:
                tmp.append(p.sub("\n", i))
            #end for
            
            datalist = tmp
            
            for item in datalist:
                items = item.split("\n")
                
                first_line = items[0].strip()
                
                p1 = re.compile(r"^(.+) information")
                p2 = re.compile(r"^Port.+\((.+)\)")
                
                if len(p1.findall(first_line)) == 1:
                    proto = p1.findall(first_line)[0]
                    port = 0
                elif len(p2.findall(first_line)) == 1:
                    proto = p2.findall(first_line)[0].split("/")[1]
                    port = p2.findall(first_line)[0].split("/")[0]
                else:
                    proto = ""
                    port = 0
                #end if

                p = re.compile(r"Plugin ID (\d{1,6})")
                
                vul_ids = p.findall(item)
                if len(vul_ids) > 0:
                    vul_num = len(vul_ids)
                    p = re.compile(r"Plugin ID ([\s\S]*?)(?:\[.\]|$)")
                    vul_datas = p.findall(item)
                    if len(vul_datas) == vul_num:
                        p = re.compile(r"Plugin output :([\s\S]*?)(?:CVE|$)")
                        for vul_data in vul_datas:
                            vul_output = p.findall(vul_data)
                            if len(vul_output) == 1:
                                vul_output = self.outputDecode(vul_output[0])
                            else:
                                vul_output = ""
                            #end if
                            
                            vul_id = vul_ids[vul_datas.index(vul_data)]
                            
                            return_result.append({'vul_id':int(vul_id),'port':int(port),'proto':proto,'output':vul_output})
                        #end for
                    #end if
                #end if
            #end for
            
            return return_result
        except Exception, e:
            logger.error(e)
            return []
        #end try
    #end def

    def stripVulList(self, vulList):
        tmp = []
        ret = []
        for i in vulList:
            if (str(i['vul_id']) + "#" + str(i['port'])) not in tmp:
                ret.append(i)
                tmp.append(str(i['vul_id']) + "#" + str(i['port']))
            else:
                continue
            #end if
        #end for
        return ret
    #end def

    def checkIfLogCve(self, vulId):
        try:
            need_log_cve = []
            need_log_cve.append(3)
            need_log_cve.append(27)
            need_log_cve.append(29)
            need_log_cve.append(31)
            
            res = self.dao.getRowData('host_vul_family_ref', {'vul_id':vulId}, 'family')
            if res['family'] in need_log_cve:
                return True
            #end if
            
            return False
        except Exception, e:
            logger.error(e)
            return False
        #end try
    #end def
    
    def updateCveResult(self, ob):
        try:
            cve = ob['cve']
            port = ob['port']
            proto = ob['proto']
            ip = ob['ip']
            family = ob['family']
            level = ob['level']
            output = ob['output']
            metasploit = ob['metasploit']
          
            if cve is None or cve == '':
                return False
            #end if

            cve_list = cve.split(',')
            for cve_item in cve_list:
                cve_item = cve_item.strip()
                res = select.dao.getRowData('cve_info', {'cve_id':cve_item})
                if res and len(res) > 0:
                    cve = res['cve_id']
                    vul_id = '0'
                    cnnvd = res['cnnvd']
                    vul_name = res['vul_name']
                    desc = res['abstruct']
                    solution = res['notice']
                    ref = res['ref']

                    if self.dao.getDataCount('host_result', {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'cve':cve,'ip':ip,'port':port}) > 0:
                        continue
                    #end if
                    
                    insert = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'vul_id':vul_id,'cve':cve,'cnnvd':cnnvd,'level':level,'vul_name':vul_name,'desc':desc,'solution':solution,'ref':ref,'output':output,'family':family,'port':port,'proto':proto,'metasploit':metasploit}
                    self.dao.insertData('host_result', insert)
                #end if
            #end for
        except Exception, e:
            logger.error(e)
        #end try 
    #end def

    def updateWeakPwdResult(self, ip, vul_name, username, password, port, proto):
        try:
            if self.dao.getDataCount('weak_pwd_result', {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'vul_name':vul_name,'username':username,'password':password,'port':port,'proto':proto}) > 0:
                return
            #end if

            insert = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip,'vul_name':vul_name,'username':username,'password':password,'port':port,'proto':proto}
            self.dao.insertData('weak_pwd_result', insert)
        except Exception, e:
            logger.error(e)
        #end try
    #end def

    def updateHostResult(self, scanRes):
        try:
            scanRes = self.stripVulList(scanRes)

            for vul in scanRes:
                vul_id = vul['vul_id']
                port = vul['port']
                proto = vul['proto']
                output = vul['output']

                if int(vul_id) == 41028:
                    self.updateWeakPwdResult(ip, "SNMP默认团体名","public","public", port, proto)
                #end if
 
                if int(vul_id) == 10660:
                    self.updateWeakPwdResult(ip, "ORACLE","tnslsnr","空密码", port, proto)
                #end if
                
                if int(vul_id) == 17162:
                    self.updateWeakPwdResult(ip,"Sybase","SA","空密码", port, proto)
                #end if
                
                if int(vul_id) == 10481:
                    self.updateWeakPwdResult(ip,"MYSQL","root","空密码", port, proto)
                #end if

                insert = {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'vul_id':vul_id,'ip':ip,'port':port,'proto':proto,'output':output}
                re = self.dao.getRowData('host_vul_list', {'vul_id':vul_id})
                if re:
                    insert['level'] = re["risk_factor"]
                    insert['vul_name'] = re["vul_name_cn"]
                    insert['desc'] = re["desc_cn"]
                    insert['solu'] = re["solu_cn"]
                    insert['ref'] = re["ref_cn"]

                    sql = "select `desc` from host_family_list where id = (select family from host_family_ref where vul_id = %d)" % int(vul_id)
                    tmp_family = self.dao.getRowDataBySql(sql)
                    if tmp_family:
                        insert['family'] = tmp_family["desc"]
                    else:
                        insert['family'] = ''
                    #end if
                    insert['cve'] = re["cve"]
                    insert['cnnvd'] = re["cnnvd"]
                    insert['cnvd'] = re["cnvd"]
                    insert['metasploit'] = re["metasploit"]
                    
                    self.dao.insertData('host_result', insert)

                    if len(insert['cve'].strip().split(',')) > 1 and self.checkIfLogCve(vul_id):
                        ob = {}
                        ob['cve'] = insert['cve']
                        ob['family'] = insert['family']
                        ob['port'] = insert['port']
                        ob['proto'] = insert['protot']
                        ob['ip'] = insert['ip']
                        ob['level'] = insert['level']
                        ob['output'] = insert['output']
                        ob['metasploit'] = insert['metasploit']
                        self.updateCveResult(ob)
                    #end if
                #end if
            #end for
        except Exception, e:
            logger.error(e)
        #end try
    #end def
    
    def run(self):
        try:
            cmd = "%s -sS -p 1-9999 -V -i %s %s" % (NASL_EXE, self.vulIds, self.ip)
            logger.debug(cmd)
            popenData = popen(cmd)
            res = self.handleResult(popenData)

            self.updateHostResult(res)
        except Exception, e:
            logger.error(e)
        #end try
    #end def
#end class


class HostScanThread(threading.Thread):

    def __init__(self, taskCnf, target):
        threading.Thread.__init__(self)
        self.module = self.__class__.__name__
        self.taskCnf = taskCnf
        self.taskId = taskCnf['id']
        self.assetTaskId = taskCnf['asset_task_id']
        self.vulList = taskCnf['vulList']
        self.target = target
        self.dao = MysqlDao()
    #end def

    def run(self):
        try:
            while True:
                try:
                    if self.target.empty() == False:
                        try:
                            ip = self.target.get_nowait()
                        except Exception,e2:
                            continue
                        #end try
                        
                        scriptThreads = []
                        for vulIds in self.vulList:
                            scriptThreads.append(ScriptScanThread(self.taskCnf, ip, vulIds))
                        #end for
                        for t in scriptThreads:
                            t.start()
                        #end for
                
                        for t in scriptThreads:
                            t.join()
                        #end for
                        
                        self.dao.updateData('host_infos', {'host_scan_state':1}, {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'ip':ip})
                    else:
                        break
                    #end if
                except Exception, e1:
                    logger.error(e1)
                #end try
            #end while
        except Exception, e:
            logger.error(e)
        #end while
    #end def
#end class


class HostScanEngine:
    def __init__(self, taskId, action):
        self.taskId = str(taskId)
        self.action = action
        self.module = self.__class__.__name__
        self.assetTaskId = 0
        self.taskName = ''
        self.policy = 0
        self.timeout = 30
        self.thread = 10
        self.maxScript = 50
        self.vulList = []
        self.dao = MysqlDao()

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
            pid = "%sHostScanEngine-%s" % (SCANER_TEMP_DIR, self.taskId)
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
                self.dao.updateData('host_infos', {'host_scan_state':0}, {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'state':1})
                self.dao.updateData('task', {'host_scan_state':0}, {'id':self.taskId,'asset_task_id':self.assetTaskId})
                self.dao.deleteData('host_result', {'task_id':self.taskId,'asset_task_id':self.assetTaskId})
            #end if

            self.taskCnf = self.dao.getTaskData(self.taskId)
            if self.taskCnf == False:
                return False
            #end if
            self.assetTaskId = self.taskCnf['asset_task_id']
            self.timeout = self.taskCnf['host_scan_timeout']
            self.policy = self.taskCnf['host_scan_policy']
            self.taskName = self.taskCnf['name']
            self.thread = self.taskCnf['host_scan_thread']
            self.maxScript = self.taskCnf['host_scan_max_script']
            self.startTime = time.time()

            res = self.dao.getData('host_vul_policy_ref', {'policy_id':self.policy}, 'vul_id')
            t = []
            for vul in res:
                t.append(str(vul['vul_id']))

                if len(t) > self.maxScript:
                    self.vulList.append(','.join(t))
                    t = []
                #end if
            #end for
            if len(t) > 0:
                self.vulList.append(','.join(t))
            #end if
            self.taskCnf['vulList'] = self.vulList

            return True
        except Exception, e:
            logger.error(e)
            return False
        #end try
    #end def

    def finish(self):
        try:
            if self.dao.getDataCount('host_infos', {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'state':1,'host_scan_state':0}) == 0:
                self.dao.updateData('task', {'host_scan_state':1}, {'id':self.taskId})
            #end if

            currentTime = time.strftime("%Y-%m-%d %X",time.localtime())
            self.dao.updateData('host_infos', {'end_time':currentTime}, {'task_id':self.taskId,'asset_task_id':self.assetTaskId,'state':1,'host_scan_state':1,'web_scan_state':1,'weak_pwd_scan_state':1,'port_scan_state':1,'end_time':''})
            self.dao.updateData('task', {'state':3,'end_time':currentTime}, {'id':self.taskId,'init_state':1,'prescan_state':'1','web_scan_state':1,'host_scan_state':1,'port_scan_state':1,'weak_pwd_scan_state':1})
        except Exception, e:
            logger.error(e)
        #end try
    #end def

    def run(self):
        try:
            logger.debug('Host scan is start')
            if self.init() == False:
                return
            #end if

            logger.debug('Host scan init is success')

            if self.taskCnf['host_scan_enable'] == 0:
                self.finish()
                return
            #end if

            logger.debug('Host scan is enable')

            if self.taskCnf['host_scan_enable'] == 1 and self.taskCnf['host_scan_state'] == 1:
                self.finish()
                return
            #end if

            logger.debug('Host scan is not finished')

            res = self.dao.getData('host_infos', {'task_id':self.taskId, 'asset_task_id':self.assetTaskId,'host_scan_state':0})
            if not res or len(res) <= 0:
                self.finish()
                return
            #end if

            logger.debug('find host_scan target to scan')

            for row in res:
                self.target.put(row['ip'])
            #end for

            threadList = []
            for i in range(self.thread):
                t = HostScanThread(self.taskCnf, self.target)
                threadList.append(t)
            #end for
            for t in threadList:
                t.start()
            #end for
            for t in threadList:
                t.join()
            #end for



            self.finish()
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

    hostScanEngine = HostScanEngine(taskId, action)
    hostScanEngine.run()
#end def

if __name__ == '__main__':
    main(sys.argv)
    exit()
#end if
