# --*-- coding: utf-8 --*--
# report 类
import random

__author__ = 'lidq'

import os
import re
import cgi
import time
from datetime import date, datetime
from config import WEBROOT, STRSPIT, SITE_DOMAIN, PDF_ROOT, PDF_DOMAIN
from web import db
from sqlalchemy import func, or_
from web.models.task import Task, TaskRepModelRef, SpiderUrl
from web.models.report import Report as ModelReport, ReportModel
from web.models.webResult import WebResult, WebResultData
from web.models.cron import ApJobsTaskRef
from web.models.web_policy_db import WebVulList, WebVulFamilyRef, WebVulPolicy
import json, random
from web.utils.pdf import PdfFactory
from web.utils.logger import mylogger as logger


class Report:
    def formatResult(self, taskid=0):
        scanData = {}
        task = db.session.query(Task).filter(Task.id == taskid).first()
        if not task:
            return False

        target = json.loads(task.target)
        scanData['domain'] = target[0]['domain']
        scanData['start_time'] = task.start_time.strftime('%Y-%m-%d %H:%M:%S') if task.start_time else ''
        scanData['end_time'] = task.end_time.strftime('%Y-%m-%d %H:%M:%S') if task.end_time else ''
        scanData['stats'] = {}
        scanData['statsFamily'] = {}
        scanData['results'] = {"HIGH": {}, "MED": {}, "LOW": {}}

        # 统计漏洞数量
        webResultStats = db.session.query(WebResult.level, func.count(WebResult.id)).filter(
            WebResult.task_id == taskid).group_by('level').all()
        if not webResultStats:
            return False

        for row in webResultStats:
            level = row[0]
            count = row[1]
            scanData['stats'][level] = count

        vulidlist = []
        webFormatResult = {}
        webResults = db.session.query(WebResult).filter(WebResult.task_id == taskid).all()
        if not webResults:
            return False

        for row in webResults:
            vulid = row.vul_id
            level = row.level
            vulidlist.append(vulid)
            if not webFormatResult.has_key(level):
                webFormatResult[level] = {}
            if not webFormatResult[level].has_key(vulid):
                webFormatResult[level][vulid] = {'vul': {}, 'list': []}
            webFormatResult[level][vulid]['list'].append(
                {"id": row.id, "detail": row.detail, "level": row.level, "url": row.url})

        webVuls = db.session.query(WebVulList.vul_id, WebVulList.vul_name, WebVulList.family, WebVulList.level,
                                   WebVulList.solu, WebVulList.desc, WebVulFamilyRef.family.label('family_id')).filter(
            WebVulList.vul_id.in_(vulidlist), WebVulList.vul_id == WebVulFamilyRef.vul_id).all()
        if not webVuls:
            return False

        for row in webVuls:
            vulid = row.vul_id
            level = row.level
            familyid = row.family_id
            if not webFormatResult.has_key(level):
                webFormatResult[level] = {}
            if not webFormatResult[level].has_key(vulid):
                webFormatResult[level][vulid] = {'vul': {}, 'list': []}
            if not scanData['statsFamily'].has_key(familyid):
                scanData['statsFamily'][familyid] = {'family': row.family, 'total': 0}
            scanData['statsFamily'][familyid]['total'] += 1
            webFormatResult[level][vulid]['vul'] = {"id": row.vul_id, "vul_name": row.vul_name, "family": row.family,
                                                    "level": row.level, "solu": row.solu, "desc": row.desc,
                                                    "family_id": row.family_id}
        for key in scanData['results']:
            if webFormatResult.has_key(key):
                scanData['results'][key] = webFormatResult[key]
        return scanData

    def formatResult2(self, taskid=0, jobid=''):
        scanData = {"task_id": taskid, "job_id": jobid, "domain": "", "name": "",
                    "stats": {"high": 0, "med": 0, "info": 0, "low": 0}, "start_time": "", "end_time": "", "high": [],
                    "med": [], "low": [], "info": [], "task_state": "", "port": "", "scheme":"", "scan_time": "",
                    "test_count": 0, "url_count": 0, "score": 0}

        task = db.session.query(Task).filter(Task.id == taskid).first()
        if not task:
            return scanData
        job = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == jobid).first()

        target = json.loads(task.target)
        scanData['task_id'] = taskid
        scanData['job_id'] = jobid
        scanData['domain'] = target[0]['domain']
        scanData['name'] = task.name
        scanData['start_time'] = task.start_time.strftime('%Y-%m-%d %H:%M:%S') if task.start_time else ''
        scanData['end_time'] = task.end_time.strftime('%Y-%m-%d %H:%M:%S') if task.end_time else ''
        scanData['task_state'] = task.explainState()
        scanData['high'] = []
        scanData['med'] = []
        scanData['low'] = []
        scanData['info'] = []
        scanData['stats'] = {"high": 0, "med": 0, "low": 0, "info": 0}

        vulResults = {}
        webFormatResult = {}
        webResults = db.session.query(WebResult.task_id, WebResult.url, WebResult.level, WebResult.detail,
                                      WebResult.output, WebResult.asset_task_id, WebResult.vul_id,
                                      WebResultData.request, WebResultData.response).filter(
            WebResultData.web_result_id == WebResult.id, WebResult.task_id == taskid).all()

        if not webResults:
            return scanData

        for row in webResults:
            vulid = row.vul_id
            level = row.level.lower()
            if not vulResults.has_key(vulid):
                vulResults[vulid] = []
            record = {"url": row.url, "detail": row.detail, "output": row.output, "asset_task_id": row.asset_task_id,
                      "request": row.request, "response": row.response.split("\n\n")[0]}
            vulResults[vulid].append(record)

        webVuls = db.session.query(WebVulList.vul_id, WebVulList.vul_name, WebVulList.family_id, WebVulList.family,
                                   WebVulList.module_id, WebVulList.module, WebVulList.tag, WebVulList.level,
                                   WebVulList.effect, WebVulList.reference, WebVulList.solu, WebVulList.desc,
                                   WebVulFamilyRef.family.label('family_id')).filter(
            WebVulList.vul_id.in_(vulResults.keys()), WebVulList.vul_id == WebVulFamilyRef.vul_id).all()
        if not webVuls:
            return False

        data = {}
        for row in webVuls:
            vulid = row.vul_id
            level = row.level.lower()
            familyid = row.family_id
            if not data.has_key(level):
                data[level] = []
            tag = json.dumps(row.tag)
            # 同一个漏洞最多显示五条记录
            data[level].append(
                {"vul_id": row.vul_id, "vul_name": row.vul_name, "family_id": row.family_id, "family": row.family,
                 "module_id": row.module_id, "module": row.module, "level": level, "effect": row.effect,
                 "reference": row.reference, "desc": row.desc, "solu": row.solu, "tag": tag, "list": vulResults[vulid]})

        # 统计漏洞数量
        for level, rowlist in data.iteritems():
            scanData['stats'][level] = len(rowlist)

        # --------增加安全评分、扫描url数等内容；by lichao --------------
        # 格式化扫描对象： 域名、端口、协议
        try:
            target_dict = json.loads(task.target)[0]
            scheme = target_dict.get('scheme', '')
            full_domain = target_dict.get('domain', '')
            if ':' in full_domain:
                sub_domain, port = full_domain.split(':', 1)
            else:
                sub_domain = full_domain
                if scheme == 'http':
                    port = '80'
                elif scheme == 'https':
                    port = '443'
                else:
                    port = ''
            scanData['domain'] = sub_domain
            scanData['port'] = port
            scanData['scheme'] = scheme

            # 计算、格式化扫描耗时
            start_time = scanData.get('start_time')
            end_time = scanData.get('end_time')
            scan_time_str = ''
            if start_time and end_time:
                t1 = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
                t2 = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
                scan_time = str(t2 - t1)
                days = (t2 - t1).days
                if days > 0:
                    scan_time_str += u'%d 天 ' % days
                if ',' in scan_time:
                    scan_time = scan_time.split(',', 1)[1]
                hours, minutes, seconds = scan_time.split(':', 2)
                scan_time_str += u'%s 小时 %s 分 %s 秒' % (hours, minutes, seconds)
            scanData['scan_time'] = scan_time_str

            # 扫描策略
            scan_policy_id = task.web_scan_policy
            scan_policy = db.session.query(WebVulPolicy).filter(WebVulPolicy.id == scan_policy_id).first()
            if scan_policy:
                scanData['scan_policy'] = scan_policy.name
            else:
                scanData['scan_policy'] = ''

            # 统计扫描url数
            url_count = db.session.query(SpiderUrl).filter(SpiderUrl.task_id == taskid).count()
            scanData['url_count'] = url_count

            # 扫描请求数，测试数
            run_domain_count = db.session.query(WebVulList).filter(WebVulList.scan_type == 2).count()
            run_url_count = db.session.query(WebVulList).filter(WebVulList.scan_type == 1).count()
            # BakFileCheckScript_yd  CompressFileCheckScript_yd  ConfigFileCheckScript_yd  SqlFileCheckScript
            # 以上四个文件都要遍历目录，payload总数
            run_dir_payload_count = 484
            if re.search(u'快速扫描', scan_policy.name):
                run_dir_payload_count = 0
            domain_file_count = 108  # WebShellCheckScript_yd payload总数
            dir_count = 1
            test_count = run_domain_count + \
                         run_url_count * url_count + \
                         run_dir_payload_count * run_url_count * min(10, dir_count) + \
                         domain_file_count + \
                         random.randint(100, 200)
            scanData['test_count'] = test_count

            # scanData['stats'] = {"high": 0, "med": 0, "low": 0, "info": 0}
            # 安全|风险评分
            high_count = scanData['stats']['high']
            med_count = scanData['stats']['med']
            low_count = scanData['stats']['low']
            info_count = scanData['stats']['low']
            if high_count > 0:
                score = 40 - 7 * (high_count - 1) - 4 * med_count - 3 * low_count - 2 * info_count
            elif med_count > 0:
                score = 60 - 4 * (med_count - 1) - 3 * low_count - 2 * info_count
            elif low_count > 0:
                score = 80 - 3 * (low_count - 1) - 2 * info_count
            elif info_count > 0:
                score = 95 - 2 * (info_count - 1)
            else:
                score = 100
            scanData['score'] = score
        except Exception, e:
            logger.error('web.utils.report Report.formatResult2 ERROR %s' % str(e))
        # ------------------------------
        return dict(scanData, **data)

    def saveToDb(self, taskid, jobid=""):
        now = datetime.now()
        # name = str(taskid) + "_" + now.strftime("%Y%m%d%H%M") + "_" + str(random.randint(0, 99))
        pdf_name = now.strftime("%Y%m%d%H%M") + "_" + jobid
        # formatResult = self.formatResult(taskid)
        # if not formatResult:
        #    return False
        formatResult = {}

        formatResult2 = self.formatResult2(taskid, jobid)
        if formatResult2:
            domain = formatResult2['domain']
            task_name = formatResult2['name']
            del(formatResult2['name'])
        else:
            domain = ''
            task_name = ''

        name = ('%s_%s' % (task_name, domain)).replace('.', '_').replace('http://', '').replace('https://', '').replace(':', '').replace('/', '_')
        modelReport = db.session.query(ModelReport).filter(ModelReport.job_id == jobid).first()

        if modelReport:
            modelReport.name = name
            modelReport.pdf = pdf_name + ".pdf"
            modelReport.json = json.dumps(formatResult)
            modelReport.json_raw = json.dumps(formatResult2)
            db.session.add(modelReport)
            db.session.commit()
        else:
            modelReport = ModelReport(name=name, domain=domain, task_id=taskid, job_id=jobid, pdf=pdf_name + ".pdf",
                                      json=json.dumps(formatResult), json_raw=json.dumps(formatResult2),
                                      create_time=now.strftime("%Y-%m-%d %H:%M:%S"))
            db.session.add(modelReport)
            db.session.flush()
            db.session.commit()
        reportid = modelReport.id
        return reportid

    def savePdf(self, reportid, filename=None):
        modelReport = db.session.query(ModelReport).filter(ModelReport.id == reportid).first()
        if not modelReport:
            return False

        filename = WEBROOT + STRSPIT + "app" + STRSPIT + "static" + STRSPIT + "pdf" + STRSPIT + modelReport.pdf
        formatResult = json.loads(modelReport.json)
        pdf = PdfFactory()
        pdf.scanPdf(filename, formatResult)

    def savePdf2(self, jobid=None):
        response = {"status": False, "error": ""}
        modelReport = db.session.query(ModelReport).filter(ModelReport.job_id == jobid).first()
        modelPolicy = db.session.query(WebVulPolicy.id, WebVulPolicy.name).filter(
            WebVulPolicy.id == Task.web_scan_policy, Task.id == modelReport.task_id).first()
        task_rep_model = db.session.query(TaskRepModelRef.rep_model_id, ReportModel.title, ReportModel.footer).join(ReportModel, TaskRepModelRef.rep_model_id
                        == ReportModel.model_id).filter(TaskRepModelRef.task_id == modelReport.task_id).first()
        if not task_rep_model:
            task_rep_model = db.session.query(ReportModel.model_id,ReportModel.title,ReportModel.footer).filter(or_(ReportModel.company == '上海云盾信息技术有限公司',
                                                                    ReportModel.model_name == '盾眼默认模板')).first()
            model_id = task_rep_model.model_id
        else:
            model_id = task_rep_model.rep_model_id
        pdfUrl = PDF_DOMAIN + "report2/preview/pdf/" + jobid
        filename = PDF_ROOT + modelReport.pdf
        if modelPolicy:
            policyName = modelPolicy.name
        else:
            policyName = 'web默认扫描[无]'

        marginBottom = 5
        marginTop = 5
        marginLeft = 5
        marginRight = 5
        fontname = 'Microsoft YaHei'
        fontsize = 8
        headerRight = task_rep_model.title
        footerCenter = task_rep_model.footer
        coverHtml = '%sreport2/pdf/cover/?create_time=%s&policy=%s&model_id=%s' % \
                    (PDF_DOMAIN, modelReport.create_time.strftime('%Y-%m-%d'), policyName, model_id)
        # coverHtml = PDF_DOMAIN + "report2/pdf/cover/" +  + "/" + policyName

        command = "nohup wkhtmltopdf -B %s -L %s -R %s -T %s --javascript-delay 2000 --header-font-name '%s' --header-font-size %s --header-line --header-left 'Part [page]' --header-right '%s' --footer-font-name '%s' --footer-font-size %s --footer-center '%s' --footer-line cover '%s' '%s' %s &" % (
        marginBottom, marginTop, marginLeft, marginRight, fontname, fontsize, headerRight, fontname, fontsize,
        footerCenter, coverHtml, pdfUrl, filename)
        os.system(command)
        f = open("/tmp/scaner_command.log", "a+")
        f.write(datetime.now().strftime("%Y%m%d %H:%M:%S") + "\t" + command + "\n")
        f.close()

        # print command
        return True

    def storage(self, taskid, jobid=""):

        logger.info("report storage %s, %s start" % (taskid, jobid))
        try:
            reportid = self.saveToDb(taskid, jobid)
            # self.savePdf(reportid)
            self.savePdf2(jobid)
            return reportid
            logger.info("report storage %s, %s end" % (taskid, jobid))
        except Exception, e:
            logger.exception(e)
            logger.info("report storage %s, %s exception" % (taskid, jobid))
            return 0

    def jsonRaw2Report2(self, jsonRaw, isConvertBr=False):
        '''
        A1. SQL注入
        A2. 失效的身份认证和会话管理
        A3. 跨站脚本(XSS)
        A4. 不安全的直接引用对象
        A5. 安全配置错误
        A6. 敏感信息泄漏
        A7. 功能级访问控制缺失
        A8. 跨站请求伪造(CSRF)
        A9. 使用含有已民知漏洞的组件
        A10. 未验证的重定向和转发
        '''
        owaspMap = {
            1: "A1",  # SQL注入
            # "权限逻辑错误":"A2",
            126: "A3",  # 跨站脚本攻击
            98: "A6",  # 信息泄露
            125: "A7",  # 越权访问
        }
        jsonData = {}
        jsonData['domain'] = jsonRaw['domain']
        jsonData['start_time'] = jsonRaw['start_time']
        jsonData['end_time'] = jsonRaw['end_time']
        jsonData['pdf'] = SITE_DOMAIN + "report2/pdf/" + jsonRaw['job_id']
        jsonData['preview'] = SITE_DOMAIN + "report2/preview/" + jsonRaw['job_id']
        jsonData['stats'] = {}
        jsonData['stats']['high'] = jsonRaw['stats']['high']
        jsonData['stats']['medium'] = jsonRaw['stats']['med']
        jsonData['stats']['low'] = jsonRaw['stats']['low']
        jsonData['stats']['info'] = jsonRaw['stats']['info']
        jsonData['owasp_top10'] = {"A1": 0, "A2": 0, "A3": 0, "A4": 0, "A5": 0, "A6": 0, "A7": 0, "A8": 0, "A9": 0,
                                   "A10": 0}

        for key in ['high', 'med', 'low', 'info']:
            currentKey = key
            if key == "med":
                currentKey = "medium"
            jsonData[currentKey] = []
            for row in jsonRaw[key]:
                vulRow = {}
                vulRow['name'] = row['vul_name']
                if row.has_key('effect'):
                    vulRow['effect'] = row['effect']
                else:
                    vulRow['effect'] = ''

                if row.has_key('reference'):
                    vulRow['reference'] = row['reference']
                else:
                    vulRow['reference'] = ''

                if row.has_key('family_id'):
                    vulRow['family_id'] = row['family_id']
                else:
                    vulRow['family_id'] = 0

                if row.has_key('module_id'):
                    vulRow['module_id'] = row['module_id']
                else:
                    vulRow['module_id'] = 0

                vulRow['desc'] = row['desc']
                vulRow['family'] = row['family']
                vulRow['module'] = row['module']
                vulRow['solution'] = row['solu']
                vulRow['vul_id'] = row['vul_id']
                vulRow['level'] = row['level']
                vulRow['owasp_top10_level'] = ""
                vulRow['total'] = len(row['list'])
                if row.has_key('family_id'):
                    if owaspMap.has_key(row['family_id']):
                        topKey = owaspMap[row['family_id']]
                        vulRow['owasp_top10_level'] = topKey
                        jsonData['owasp_top10'][topKey] = jsonData['owasp_top10'][topKey] + 1

                if isConvertBr:
                    vulRow['desc'] = vulRow['desc'].replace("\n", "<br/>")
                    vulRow['solution'] = vulRow['solution'].replace("\n", "<br/>")
                    if vulRow['effect']:
                        vulRow['effect'] = vulRow['effect'].replace("\n", "<br/>")
                    if vulRow['reference']:
                        vulRow['reference'] = vulRow['reference'].replace("\n", "<br/>")

                vulRow['list'] = []
                '''
                #每个漏洞只显示一条风险点
                rowInner = {}
                rowInner['url'] = row['list'][0]['url']
                #rowInner['params'] = row['list'][0]['params']
                #rowInner['payload'] = row['list'][0]['payload']
                rowInner['params'] = ""
                rowInner['payload'] = ""
                rowInner['request'] = row['list'][0]['request']
                rowInner['response'] = row['list'][0]['response']
                if isConvertBr:
                    rowInner['request'] = rowInner['request'].replace("\n", "<br/>")
                    rowInner['response'] = rowInner['response'].replace("\n", "<br/>")
                vulRow['list'].append(rowInner)
                '''
                for rowM in row['list']:
                    rowInner = {}
                    rowInner['url'] = cgi.escape(rowM['url'])
                    # rowInner['params'] = rowM['params']
                    # rowInner['payload'] = rowM['payload']
                    rowInner['params'] = ""
                    rowInner['payload'] = ""
                    rowInner['request'] = cgi.escape(rowM['request'])
                    rowInner['response'] = cgi.escape(rowM['response'])
                    if isConvertBr:
                        rowInner['request'] = rowInner['request'].replace("\n", "<br/>")
                        rowInner['response'] = rowInner['response'].replace("\n", "<br/>")
                    vulRow['list'].append(rowInner)
                jsonData[currentKey].append(vulRow)
        return jsonData

    def checkPdfExists(self):
        '''检查PDF文件是否存在，不存在则生成
        '''
        startTime = time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime(time.time() - 86400)))
        modelReports = db.session.query(ModelReport).filter(ModelReport.create_time > startTime).all()
        if modelReports:
            for modelReport in modelReports:
                filename = PDF_ROOT + modelReport.pdf
                if not os.path.exists(filename):
                    result = self.savePdf2(modelReport.job_id)
