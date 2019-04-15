#!/usr/bin/python
# -*- coding: utf-8 -*-

from ScanScriptForDomain import *
from ScanScriptForUrl import *
from db.MysqlDao import *
from random import random
from time import time as c_time
from engine_lib import yd_json as json
from logger import scanLogger as logger
import datetime
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from sqlalchemy import func
from common.sql_orm import DBSession
from common.spider_models import ScanSpiderUrl, WebVulList
from time import sleep


def get_site_dirs(task_id):
    site_dirs = []
    try:
        db_session = DBSession()
        url_dirs = db_session.query(func.group_concat(ScanSpiderUrl.url_dir))\
            .filter(ScanSpiderUrl.task_id == task_id).group_by(ScanSpiderUrl.task_id).first()
        if url_dirs:
            url_dir_list = url_dirs[0].split(',')
            site_dirs = list(set(url_dir_list))
        db_session.close()
    except Exception, e:
        print e
    return site_dirs


def os_fingerprint(target_ip):
    # param source_ip: 源站IP，不填则不做操作系统类型（linux|windows .etc）指纹检测
    if not target_ip:
        return None
    report = None
    nm = NmapProcess(targets=target_ip, options='-O')
    rc = nm.run()
    if rc != 0:
        return report
    try:
        report = NmapParser.parse(nm.stdout)
    except:
        pass
    os_name = None
    if report:
        host = report.hosts[0]
        if host.os_fingerprinted:
            for osm in host.os.osmatches:
                if osm.accuracy >= 90:  # 符合某操作系统指纹几率大于90%, 就取该指纹
                    os_name = osm.name
                break
    if not os_name:
        return 'unknown'

    if re.search('linux', os_name, re.I):
        return 'linux'
    elif re.search('windows', os_name, re.I):
        return 'windows'
    else:
        return 'unknown'


def web_server_fingerprint(scheme, source_ip, domain, path):
    '''

    :param scheme: http|https
    :param domain: 域名
    :param path: 起始路径，默认为'/'
    :return:
    '''
    try:
        url = '%s://%s%s' % (scheme, source_ip if source_ip else domain, path if path else '/')
        headers = {'Host': domain, 'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
        # request = urllib2.Request(url=url, headers=headers)
        # response = urllib2.urlopen(request)
        # header_content = response.headers
        http = HttpRequest({'domain': domain, 'timeout': 30, 'follow_redirects':True})
        res, content = http.request(url=url, method='GET', headers=headers)
        server = res.get('server')
        if not server:
            return 'unknown'
        if re.search('apache', server, re.I):
            return 'apache'
        elif re.search('nginx', server, re.I):
            return 'nginx'
        elif re.search('microsoft|iis', server, re.I):
            return 'iis'
        else:
            return server
    except Exception, e:
        logger.error("File: ScanSite.py, web_server_fingerprint function failed :%s" % (str(e)))
        return 'unknown'


def get_invaild_page_bak(scheme, source_ip, domain):
    current_time = c_time()
    random_num = random()
    new_domain = source_ip if source_ip else domain
    path_404 = ('/%f%f' % (current_time, random_num)).replace('.', '/')
    url_404 = "%s://%s%s.abc" % (scheme, new_domain, path_404)  # 用当前时间戳和随机数构成不存在的url，后缀.abc
    header = {'Host': domain}
    # --- update by mochj after testing the rule_scan
    http = HttpRequest({'timeout': 30, 'follow_redirects': True})
    try:
        res_404, content_404 = http.request(url_404, redirections=5, headers=header)
        status_404 = int(res_404.get('status', 0))
    except:
        status_404 = 0
        content_404 = None
    path_waf = '?param=-1+UNION+SELECT+GROUP_CONCAT(table_name)+FROM+information_schema.tables'
    url_waf = "%s://%s%s" % (scheme, new_domain, path_waf)  # 构造一个非法url，如果有waf就会被拦截
    try:
        res_waf, content_waf = http.request(url_waf, redirections=5, headers=header)
        status_waf = int(res_waf.get('status', 0))
    except:
        status_waf = 0
        content_waf = None
    if status_waf == status_404 and content_waf == content_404:
        status_waf = None  # status_waf = None 代表waf拦截页面就是404页面，后面插件不需要做waf页面判断
        content_waf = None
    dict_404 = {'status': status_404, 'content': content_404}
    dict_waf = {'status': status_waf, 'content': content_waf}
    return dict_404, dict_waf


def get_invaild_page(scheme, source_ip, domain, site_type):
    current_time = c_time()
    random_num = random()
    new_domain = source_ip if source_ip else domain

    header = {'Host': domain}
    # --- update by mochj after testing the rule_scan
    http = HttpRequest({'timeout': 30, 'follow_redirects': True})
    # 访问不存在的文件，http服务的404页面
    path_404 = ('/%f%f' % (current_time, random_num)).replace('.', '/')
    file_404 = "%s://%s%s.css" % (scheme, new_domain, path_404)  # 用当前时间戳和随机数构成不存在的url，后缀.css
    try:
        res_file_404, content_file_404 = http.request(file_404, redirections=5, headers=header)
        status_file_404 = int(res_file_404.get('status', 0))
    except:
        status_file_404 = 0
        content_file_404 = None

    # 访问不存在的脚本，web应用的404页面, add by lichao
    if site_type:
        app_404 = "%s://%s%s.%s" % (scheme, new_domain, path_404, site_type)  # 用当前时间戳和随机数构成不存在的url，后缀.php|asp|jsp
        try:
            res_app_404, content_app_404 = http.request(app_404, redirections=5, headers=header)
            status_app_404 = int(res_app_404.get('status', 0))
        except:
            status_app_404 = 0
            content_app_404 = None
    else:
        status_app_404 = None
        content_app_404 = None

    # waf 拦截页面
    path_waf = '?param=-1+UNION+SELECT+GROUP_CONCAT(table_name)+FROM+information_schema.tables'
    url_waf = "%s://%s%s" % (scheme, new_domain, path_waf)  # 构造一个非法url，如果有waf就会被拦截
    try:
        res_waf, content_waf = http.request(url_waf, redirections=5, headers=header)
        status_waf = int(res_waf.get('status', 0))
    except:
        status_waf = 0
        content_waf = None

    if status_waf == status_file_404 and content_waf == content_file_404:
        status_waf = None  # status_waf = None 代表waf拦截页面就是404页面，后面插件不需要做waf页面判断
        content_waf = None

    if status_app_404 == status_file_404 and content_app_404 == content_file_404:
        status_app_404 = None  # status_app_404 = None 代表web服务404页面就是文件404页面，后面插件不需要做web服务404页面判断
        content_app_404 = None

    dict_file_404 = {'status': status_file_404, 'content': content_file_404}
    dict_app_404 = {'status': status_app_404, 'content': content_app_404}
    dict_waf = {'status': status_waf, 'content': content_waf}
    return dict_file_404, dict_app_404, dict_waf


class ScanSite(threading.Thread):
    def __init__(self, taskId, assetTaskId, taskCnf, threadLock):
        try:
            threading.Thread.__init__(self)
            self.module = self.__class__.__name__
            self.taskId = taskId
            self.assetTaskId = assetTaskId
            self.taskCnf = taskCnf
            self.threadLock = threadLock
            self.threadName = threading.currentThread().getName()
            self.dao = MysqlDao()
            self.count = 0

        except Exception, e:
            logger.error(e)

    def init(self):
        try:
            pass
        except Exception, e:
            logger.error(e)

    def finishSiteScan(self, siteId, ip):
        try:
            currentTime = time.strftime("%Y-%m-%d %X",time.localtime())

            progress = '|'.join(self.taskCnf['vulList'])
            siteDb = {'state':1, 'exception':'','end_time':currentTime, 'progress':progress}
            self.dao.updateData('sites', siteDb, {'id':siteId})

            self.dao.updateHostWebScanState(self.taskId, self.assetTaskId, ip)
            
            #self.clearTmpFile(self.taskId, siteId)
            
        except Exception,e:
            logger.error(e)
    
    def updateSiteException(self, content, siteId, ip):
        try:

            exceptionCount = self.dao.getSiteExceptionCount(siteId)
            if exceptionCount >= 3:
                siteDb = {'state':1, 'exception':'扫描未完成', 'exception_count': int(exceptionCount) + 1, 'next_start_time':datetime.datetime.fromtimestamp(time.time() + 5 * 60)}
                self.dao.updateData('sites', siteDb, {'id':siteId})
            else:
                siteDb = {'state':2, 'exception':'稍后继续尝试', 'exception_count': int(exceptionCount) + 1, 'next_start_time':datetime.datetime.fromtimestamp(time.time() + 5 * 60)}
                self.dao.updateData('sites', siteDb, {'id':siteId})
            
            self.dao.updateHostWebScanState(self.taskId, self.assetTaskId, ip)

        except Exception,e:
            logger.error(e)
    
    def changeCode(self,msg,code):
        if code == 'utf8' or code == 'utf-8':
            return msg
        elif code == 'gbk':
            try:
                return msg.decode('gbk').encode('utf8')
            except Exception, e:
                return msg
        elif code == 'gb2312':
            try:
                return msg.decode('gb2312').encode('utf8')
            except Exception, e:
                return msg
        else:
            try:
                return msg.decode(code).encode('utf8')
            except Exception, e:
                pass
            try:
                return msg.decode('utf8').encode('utf8')
            except Exception, e:
                pass 
            try:
                return msg.decode('gb2312').encode('utf8')
            except Exception, e:
                pass 
            try:
                return msg.decode('gbk').encode('utf8')
            except Exception, e:
                pass 
            try:
                return msg.encode('utf8')
            except Exception, e:
                pass 
            return msg
    
    def updateSiteTitle(self,content,siteId):
        try:
            title = ""
            match = re.findall(r"<(\s*)title(\s*)>(.*?)<(\s*)/(\s*)title(\s*)>",content,re.I|re.DOTALL)
            if match and len(match) > 0:
                title = match[0][2].replace("\r","").replace("\n","")
            if title == "":
                return ""
            code = self.getSiteCode(content)
            title = self.changeCode(title, code)

            siteDb = {'title': title}
            self.dao.updateData('sites', siteDb, {'id':siteId})
            
            return title
        except Exception,e:
            logger.error(e)
            return ""
    
    def getSiteCode(self, content):
        try:
            match = re.findall(r"<meta(.+?)charset(.*?)=(.+?)(\"|')", content, re.I)
            if match and len(match) > 0:
                code = match[0][2]
            else:
                code = "utf8"
            return code
        except Exception, e:
            logger.error(e)
        return "utf8"
    
    def updateSiteType(self,res,siteId):
        try:
            site_type = ""
            if res.has_key('x-powered-by'):
                site_type_x = res['x-powered-by']
                if site_type_x.lower().find('php') >= 0:
                    site_type = "php"
                elif site_type_x.lower().find('asp') >= 0:
                    site_type = "asp"
                elif site_type_x.lower().find("asp.net") >= 0:
                    site_type = "aspx"
                elif site_type_x.lower().find("jsp") >= 0:
                    site_type = "jsp"
            if site_type == "":
                if res.has_key('set-cookie'):
                    site_type_c = res['set-cookie']
                    if site_type_c.lower().find('php') >= 0:
                        site_type = "php"
                    elif site_type_c.lower().find('asp') >= 0:
                        site_type = "asp"
                    elif site_type_c.lower().find("jsessionid")>=0:
                        site_type = "jsp"
            if site_type == "":
                if res.has_key('server'):
                    server = res['server'].lower()
                    if server.lower().find('php') >= 0:
                        site_type = "php"

            if site_type != '':
                self.dao.updateData('sites', {'site_type':site_type}, {'id':siteId})

            return site_type
        except Exception,e:
            logger.error(e)
            return ''
    
    def PreSiteScan(self, url):
        try:
            http = HttpRequest({'timeout':10,'follow_redirects':False})
            res, content = http.request(url)
            return True, res, content
        except socket.timeout,e:
            logger.error(e)
            return False, {}, ''
        except Exception,e:
            logger.error(e)
            return False, {}, ''

    def checkSiteWorkMode(self,res,title):
        try:
            if res.has_key('status') and re.match('^4|5\d{2}$', res['status']):
                return False

            keyword_list = ['Internal Server Error','401 Unauthorized','Not Found','Bad Request']
            try:
                temp = u"建设中"
                keyword_list.append(temp.encode('utf8'))
                keyword_list.append(temp.encode('gb2312'))
                temp = u"使用期限已过"
                keyword_list.append(temp.encode('utf8'))
                keyword_list.append(temp.encode('gb2312'))
                temp = u"网站错误"
                keyword_list.append(temp.encode('utf8'))
                keyword_list.append(temp.encode('gb2312'))
                temp = u"崩溃"
                keyword_list.append(temp.encode('utf8'))
                keyword_list.append(temp.encode('gb2312'))
            except Exception,e1:
                logger.error(e1)

            for row in keyword_list:
                try:
                    # if title.find(row) >= 0:
                    if re.search(row, title, re.I):
                        return False
                except Exception,e1:
                    continue

            return True
        except Exception,e:
            logger.error(e)
            return True

    def checkWeb404LenRange(self, scheme, domain, path):
        try:
            max = 0
            min = 0

            http = httplib2.Http(disable_ssl_certificate_validation=True)
            http.follow_redirects = False
            socket.setdefaulttimeout(10)

            if path[-1] =='/':
                path = path[:-1]
            
            url1 = "%s://%s%s%s" % (scheme, domain, path, "/n.html")
            res, content = http.request(url1)
            if res and res.has_key('content-length'):
                min = int(res['content-length'])
            else:
                min = len(content)

            url2 = "%s://%s%s%s" % (scheme, domain, path, "/nulllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll.html")
            res, content = http.request(url2)
            if res and res.has_key('content-length'):
                max = int(res['content-length'])
            else:
                max = len(content)

            if min > max:
                t = min
                min = max
                max = t

            return min,max
        except Exception,e:
            logger.error(e)
            return 0,0
    
    def clearTmpFile(self, taskId, siteId):
        try:
            popen("rm -R /var/webs/task%s/*#%s#" % (taskId, siteId))
        except Exception,e:
            logger.error(e)
    
    def checkErrorFileStatus(self, scheme, domain, path, type, method):
        try:
            http = httplib2.Http(disable_ssl_certificate_validation=True)
            http.follow_redirects = False
            socket.setdefaulttimeout(10)
            url = "%s://%s%snulllllllllll%s" % (scheme, domain, path, type)
            if method.lower() == "head":
                res, content = http.request(url, "HEAD")
            else:
                res, content = http.request(url)
            if res and res.has_key('status') and res['status'] == '404':
                return True
            else:
                return False
        except Exception,e:
            logger.error(e)
            return False
    
    def updateHosts(self, ip, domain, taskId, siteId, action):
        try:
            if ip == domain:
                return True
            if domain.find(':') > 0:
                domain = domain.split(':')
                domain = domain[0]

            if action == 'add':
                f = file(HOSTS_PATH, "r+")
                lines = f.readlines()
                msg = "%s %s #scan#%s#%s#" % (ip, domain, taskId, siteId)
                for line in lines:
                    if line.find(msg) >= 0:
                        f.close()
                        return True
                lines.append(msg + '\n')
                f.close()

                f = file(HOSTS_PATH, "w+")
                f.writelines(lines)
                f.close()
            elif action == 'remove':
                f = file(HOSTS_PATH, "r+")
                lines = f.readlines()
                msg = "%s %s #scan#%s#%s#" % (ip, domain, taskId, siteId)
                for line in lines:
                    if line.find(msg) >= 0:
                        lines.remove(line)
                f.close()
                f = file(HOSTS_PATH, "w+")
                f.writelines(lines)
                f.close()
            else:
                return False
            
            return True
        except Exception, e:
            logger.error(e)
            return False
    
    def checkSiteId(self, siteId):
        try:
            if int(siteId) > 0:
                return True
            else:
                return False
        except Exception,e:
            logger.error(e)
            return False
    
    def checkSiteUnScaned(self):
        try:
            taskData = self.dao.getTaskData(self.taskId)
            if taskData['web_search_site_state'] == 0:
                return False

            t = {'task_id':self.taskId, 'state': 0, 'asset_task_id':self.assetTaskId}
            if self.dao.getDataCount('sites', t) > 0:
                return False

            t = {'task_id':self.taskId, 'state': 2, 'asset_task_id':self.assetTaskId}
            if self.dao.getDataCount('sites', t) > 0:
                return False
        except Exception, e:
            logger.error(e)
        return True
    
    def checkExceptionSite(self):
        flag = False
        try:
            self.threadLock.acquire()
            siteList = self.dao.getData('sites', {'state':'2','task_id':self.taskId,'asset_task_id':self.assetTaskId})

            if len(siteList) <= 0:
                flag = True

            if siteList:
                for site in siteList:
                    if site['next_start_time']:
                        if int(time.time()) > int(time.mktime(site['next_start_time'].timetuple())):
                            siteQueue.put(str(site['id']))
                            self.dao.updateData('sites', {'state':0,'exception':''}, {'id':str(site['id'])})

        except Exception,e:
            logger.error(e)
        self.threadLock.release()
        
        if flag:
            self.count += 1
            return
        
        time.sleep(30)

    def checkHeadRequest(self, scheme, domain, path):
        try:
            http = httplib2.Http(disable_ssl_certificate_validation=True)
            http.follow_redirects = False
            socket.setdefaulttimeout(10)
            
            url = "%s://%s%s" % (scheme, domain, path)
            res, content = http.request(url,"HEAD")
            if res and res.has_key('status') and res['status'] in ['200','301','302','403'] and res.has_key('content-length'):
                return True
            else:
                return False
            
        except Exception,e:
            logger.error(e)
            return False


    def scanSiteMain(self, siteId):
        try:
            logger.debug("start to scan site, siteId: %s" % (siteId))
            if siteId == None:
                return False

            dao = MysqlDao()
            siteObj = dao.getSiteData(siteId)
            if siteObj == None:
                logger.error("start to get site config exception, siteId: %s" % (siteId))
                return False

            #scheme
            scheme = siteObj['scheme'].encode('utf8')
            #ip address
            ip = siteObj['ip'].encode('utf8')
            #site domain
            domain = siteObj['domain'].encode('utf8')
            #site scan state
            state = siteObj['state']
            #site path
            path = siteObj['path'].encode('utf8')
            #site title
            title = siteObj['title'].encode('utf8')
            #site type
            siteType = siteObj['site_type'].encode('utf8')
            #site cookie
            cookie = siteObj['cookie'].encode('utf8')
            #site include url
            includeUrl = siteObj['include_url'].encode('utf8')
            if includeUrl == '':
                includeUrl = []
            else:
                includeUrl = json.read(includeUrl)
            #site exclude url
            excludeUrl = siteObj['exclude_url'].encode('utf8')
            if excludeUrl == '':
                excludeUrl = []
            else:
                excludeUrl = json.read(excludeUrl)
            #scan progress
            progress = siteObj['progress'].encode('utf8')
            #site scan policy
            policy = siteObj['policy']

            if state == 1:
                self.finishSiteScan(siteId, ip)
                return True

            #在DNS配置文件中加入这个域名的DNS信息
            # self.threadLock.acquire()
            # self.updateHosts(ip, domain, self.taskId, siteId, 'add')
            # self.threadLock.release()
            '''
            #  注释此段，在后文（代码第700行附近）重写网站存活性检测，提高稳健性，并将结果写入报告  20170804
            flag = res = content = checkOk = None
            target = []
            target.append("%s://%s%s"%(scheme,domain,path))
            # -------------UPDATE BY MCJ 扫到site即可开始扫描，无需再检测网站状态
            checkOk = True
            # for url in target:
            #     flag, res, content = self.PreSiteScan(url)
            #     if not flag:
            #         continue
            #     else:
            #         if self.checkSiteWorkMode(res, title) == False:
            #             continue
            #         else:
            #             checkOk = 1
            #             break
            # ----------
            if not checkOk:
                self.updateSiteException("网站无法访问", siteId, ip)
                return
            else:
                siteCode = self.getSiteCode(content)
                if title == "" and res and res.has_key('status') and res['status'] == '200':
                    title = self.updateSiteTitle(content, siteId)
                if siteType == "":
                    siteType = self.updateSiteType(res, siteId)
                if siteCode == "":
                    siteCode = self.getSiteCode(content)
            '''
            if self.taskCnf['web_scan_timeout']: 
                socket.setdefaulttimeout(self.taskCnf['web_scan_timeout'])

            siteDb = {'state':0, 'exception':''}
            if siteObj['start_time'] is None or siteObj['start_time'] == '0000-00-00 00:00:00':
                siteDb['start_time'] = time.strftime("%Y-%m-%d %X",time.localtime())
            if siteObj['progress'] == '':
                siteDb['progress'] = '0'
            self.dao.updateData('sites', siteDb, {'id':siteId})
            
            ###############################
            #policy:
            #    1:快速扫描，只扫描指定的域名
            #    2:完全扫描，扫描指定的域名，并且扫描二级域名
            #    3:扫描指定目录及子目录
            #    4:扫描指定的URL，这个情况下，不需要爬虫
            #    5:通过域名反查得到的域名
            #    6:登陆型扫描
            ###############################
            ## 禁用spider by mcj
            # if self.taskCnf['spider_enable'] == 1 and siteObj['spider_state'] == 0:
            #     logger.debug('spider is start')
            #
            #     progress = '0'
            #
            #     self.dao.deleteData('web_result', {'site_id':siteId})
            #     self.dao.deleteData('web_result_data', {'site_id':siteId})
            #     self.dao.deleteData('spider_url', {'site_id':siteId})
            #
            #     #开启爬虫，当扫描指定的URL时，不需要爬虫
            #     if siteObj['policy'] != 4:
            #         spiderCnf = {}
            #         spiderCnf['taskId'] = self.taskId
            #         spiderCnf['assetTaskId'] = self.assetTaskId
            #         spiderCnf['siteId'] = siteId
            #         spiderCnf['spiderUrlCount'] = self.taskCnf['spider_url_count']
            #         spiderCnf['webScanTime'] = self.taskCnf['web_scan_timeout']
            #         spiderCnf['policy'] = siteObj['policy']
            #         spiderCnf['scheme'] = siteObj['scheme'].encode('utf8')
            #         spiderCnf['domain'] = domain
            #         spiderCnf['path'] = path
            #         spiderCnf['maxTimeCount'] = 30
            #         spiderCnf['webScanTimeout'] = self.taskCnf['web_scan_timeout']
            #         spiderCnf['endTime'] = time.time() + 1800
            #         spiderCnf['maxnum'] = self.taskCnf['spider_url_count']
            #         spiderCnf['title'] = title
            #         spiderCnf['ip'] = ip
            #         spiderCnf['cookie'] = cookie
            #         spiderCnf['webSearchSiteState'] = self.taskCnf['web_search_site_state']
            #         spiderCnf['webSearchSiteTimeout'] = self.taskCnf['web_search_site_timeout']
            #         spiderCnf['includeUrl'] = includeUrl
            #         spiderCnf['excludeUrl'] = excludeUrl
            #         spiderCnf['downloadDir'] = SCANER_SPIDER_DOWNLOAD_DIR
            #
            #         if self.taskCnf['spider_type'] == 2:
            #             import Spider2 as Spider
            #         else:
            #             import Spider
            #
            #         logger.debug("spiderCnf start")
            #         logger.debug(spiderCnf)
            #         logger.debug("spiderCnf end")
            #         spider = Spider.Spider(spiderCnf)
            #         spider.start()
            #
            #     logger.debug('spider is end')

            self.dao.updateData('sites', {'spider_state':1}, {'id':siteId})

            siteCnf = dao.getSiteData(siteId)
            domain = siteCnf['domain'].encode('utf8')
            path = siteCnf['path'].encode('utf8')


            #检测网站的状态，有的网站访问后直接访问500或者其他的情况。
            if self.checkSiteWorkMode({}, title) == False:
                self.finishSiteScan(siteId, ip)
                return

            logger.debug('get site scan config')

            scanCnf = {}
            scanCnf['taskId'] = self.taskId
            scanCnf['assetTaskId'] = self.assetTaskId
            scanCnf['siteId'] = siteId
            scanCnf['maxThread'] = 10
            scanCnf['scriptThread'] = 10
            scanCnf['webTimeout'] = self.taskCnf['web_scan_timeout']
            scanCnf['ip'] = ip
            # 新增源站ip参数，add by mcj
            target = json.read(str(self.taskCnf['target']))
            source_ip = target[0].get('source_ip')
            if source_ip:
                scanCnf['source_ip'] = source_ip
            scanCnf['scheme'] = scheme
            scanCnf['domain'] = domain
            scanCnf['path'] = path
            scanCnf['errorCount'] = 0
            scanCnf['errorLenDict'] = {}
            scanCnf['maxTimeoutCount'] = 20
            scanCnf['cookie'] = cookie
            scanCnf['len404'] = []
            scanCnf['isForce'] = 0
            scanCnf['excludeUrl'] = excludeUrl
            scanCnf['threadLock'] = threading.Lock()
            scanCnf['isstart'] = '1'

            # ----------- 判断网站存活性, 如存活，获取cookie等内容 by lichao
            if source_ip:
                test_url = "%s://%s%s" % (scheme, source_ip, path)
            else:
                test_url = "%s://%s%s" % (scheme, domain, path)
            test_header = {'Host': domain}
            checkOk, siteCode = False, None
            for i in range(3):
                try:
                    http = HttpRequest({'domain': domain, 'timeout': 15, 'follow_redirects': True, 'cookie': cookie})
                    res, content = http.request(test_url, 'GET', headers=test_header)
                    if self.checkSiteWorkMode(res, title):
                        siteCode = self.getSiteCode(content)
                        if not title:
                            title = self.updateSiteTitle(content, siteId)
                        if not siteType:
                            siteType = self.updateSiteType(res, siteId)
                        if not cookie:
                            cookie = res.get('set-cookie')
                        checkOk = True
                        break
                    else:
                        sleep(5)
                except:
                    sleep(5)

            if cookie:
                scanCnf['cookie'] = cookie
            if title:
                scanCnf['title'] = title
            if siteType:
                scanCnf['siteType'] = siteType
            if siteCode:
                scanCnf['siteCode'] = siteCode

            if not checkOk:
                self.updateSiteException("网站无法访问", siteId, ip)
            # --------------------------------------------

            # ------------------- 检测网站建站系统指纹 by lichao 预留功能，暂时没有用到
            # if checkOk:
            #     from engine.engine_utils.check_web_fingerprint import web_frame_fingerprint
            #     scanCnf['web_frame'] = web_frame_fingerprint(ob=scanCnf)
            # -------------------

            # ----------- get sites_dirs by mcj
            site_dirs = get_site_dirs(self.taskId)
            scanCnf['site_dirs'] = site_dirs
            # -----------
            # ---------------- get web fingerprint  by lichao
            if checkOk:
                scanCnf['webServer'] = web_server_fingerprint(scheme, source_ip, domain, path)  # 'apache|nginx|iis|unknown'
                scanCnf['os'] = os_fingerprint(source_ip)  # 'linux|windows|unknown'
            # -----------------

            # ---------------- verify 404 page and waf page by lichao
            scanCnf['404_page'], scanCnf['app_404_page'], scanCnf['waf_page'] = get_invaild_page(scheme, source_ip, domain, siteType)
            scanCnf['404_page']['similar_rate'] = 0.8
            scanCnf['app_404_page']['similar_rate'] = 0.8
            scanCnf['waf_page']['similar_rate'] = 0.8
            # ---------------------------

            # 判断该域名扫描进度，加载未扫描的漏洞ID
            logger.debug('load unscaned script start')
            scanVulList = []
            progress = progress.split('|')
            for vulId in self.taskCnf['vulList']:
                if vulId not in progress:
                    scanVulList.append(vulId)

            logger.debug('script scan is start')
            if len(scanVulList) > 0:
                urlList = []
                if policy == 4:
                    for url in includeUrl:
                        if url in excludeUrl:
                            continue
                        t = url.split('?')
                        url = t[0]
                        params = ''
                        if len(t) > 1:
                            params = t[1]
                        urlList.append({'url':url,'params':params,'method':'get'})
                else:
                    res = self.dao.getUrlList(siteId)
                    for r in res:
                        url = r['url'].encode('utf8')
                        if nonascii(url): url = safeUrlString(url)
                        urlList.append({'url':url,'params':r['params'].encode('utf8'),'method':r['method'].encode('utf8'),'refer':r['refer'].encode('utf8')})

                # ----------- 检测网站存活性 by lichao  拿到检测网站存活性的插件id
                check_ok_vul_id = ""
                db_session = DBSession()
                try:
                    vul = db_session.query(WebVulList).filter(WebVulList.script == 'check_web_alive').first()
                    check_ok_vul_id = str(vul.id)
                except Exception, e:
                    logger.error(e)
                db_session.close()
                # -----------

                for vulId in scanVulList:
                    from time import time as during_time
                    t1 = during_time()
                    vulId = vulId.replace(" ","")
                    if vulId == "":
                        continue

                    # ----------- 检测网站存活性 by lichao
                    if not checkOk and len(urlList) <= 1:  # 判断网站无法访问
                        if vulId != check_ok_vul_id:  # 网站无法访问时，只运行 check_web_alive 这一个插件
                            continue
                    else:  # 网站可以访问时
                        if vulId == check_ok_vul_id:  # 网站可以访问时，不运行 check_web_alive 这个插件
                            continue
                    # ------------

                    progress.append(vulId)
                    self.dao.updateData('sites', {'progress':'|'.join(progress)}, {'id':siteId})
                    self.dao.deleteData('web_result', {'vul_id':vulId, 'site_id':siteId})
                
                    scanCnf['vulId'] = vulId
                    scanCnf['vulName'] = self.taskCnf['vulDict'][vulId]['vul_name']
                    scanCnf['level'] = self.taskCnf['vulDict'][vulId]['level'].encode('utf8')
                    scanCnf['scanType'] = self.taskCnf['vulDict'][vulId]['scan_type']
                    scanCnf['script'] = self.taskCnf['vulDict'][vulId]['script']
                    scanCnf['status'] = '0'
                    scanCnf['endTime'] = time.time() + 1800
                    scanCnf['timeoutCount'] = 0

                    #测试爬虫爬出来的路径
                    if scanCnf['scanType'] == 1:
                        scanCnf['queue'] = Queue()
                        for r in urlList:
                            scanCnf['queue'].put(r)
                        scanUrlScript = ScanScriptForUrl(scanCnf)
                        scanUrlScript.start()
                
                    #如果只测试指定的URL则不需要运行测试域名和测试漏洞库
                    if policy != 4:
                        #测试域名
                        if scanCnf['scanType'] == 2:
                            scanDomainScript = ScanScriptForDomain(scanCnf)
                            scanDomainScript.start()
                    duration = during_time()-t1
                    # -----------统计插件运行时间 by mcj
                    try:

                        from common.plugin_speed import PluginSpeed
                        db_session = DBSession()
                        plu_speed = PluginSpeed(self.taskId, vulId, duration)
                        db_session.add(plu_speed)
                        db_session.commit()
                        db_session.close()
                    except Exception, e:
                        logger.info(str(e))
                        db_session.rollback()
                        db_session.close()
                    # -----------统计插件运行时间 by mcj
                    if not checkOk and len(urlList) <= 1:
                        break
                urlList = []

            #结束扫描
            self.finishSiteScan(siteId, ip)
            self.threadLock.acquire()
            self.updateHosts(ip, domain, self.taskId, siteId, 'remove')
            self.threadLock.release()

            return None
        except Exception, e:
            logger.error(e)
            return siteId

    def run(self):
        try:
            logger.debug('start to scan site')
            i = 0
            while True:
                i += 1
                logger.debug("try to find new site, i: %d" % (i))
                try:
                    self.threadLock.acquire()
                    checkSiteUnscand = self.checkSiteUnScaned()
                    self.threadLock.release()
                    if checkSiteUnscand:
                        break

                    siteId = None
                    try:
                        siteId = siteQueue.get(True, 30)
                    except Exception, ge:
                        pass

                    #开始这个域名的扫描
                    if siteId and self.checkSiteId(siteId):
                        self.count = 0
                        logger.debug("find new site to scan, siteId: %s" % (siteId))
                        self.scanSiteMain(str(siteId))

                    self.checkExceptionSite()
                except Exception, e1:
                    logger.error(e1)
                    self.count += 1
                if self.count > 2:
                    break
            logger.debug('end to scan site')
        except Exception, e:
            logger.debug(e)


