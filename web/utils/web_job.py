# --*-- coding: utf-8 --*--
import json
import sys
import os
import urlparse
from copy import deepcopy

import httplib2
from common.spider_models import ScanSpiderUrlOther
from config import SPIDER_URL, SPIDER_TOKEN, SPIDER_LIMIT_TIME
from web.api_1_0.patch_report import send_patch_rep, send_over_view_rep, _sort_patch_rep, notify_tsgz_task
from web.models.report import PatchReport, PatchTask
from web.models.spider_url_other import SpiderUrlOther
from web.utils.url_filter import get_url_element

pro_dir = os.path.abspath(os.path.pardir)
sys.path.insert(0, pro_dir)
from engine.WebScanEngine import WebScanEngine
from web.models.task import Task, SpiderUrl
from web.utils.report import Report
from datetime import datetime
from flask import jsonify
from web import db, logger
from web.models.cron import ApJobsTaskRef, SpiderJob
from scan_spider.spider import Spider
from ext import celery


@celery.task(bind=True)
def run_engine(self, task_id, action, spider_flag, spider_exec_id=None):
    print 'run_engine'

    self.update_state(state='STARTED')
    job_id = self.request.id
    job_task_ref = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).first()
    job = self.AsyncResult(job_id)
    job_task_ref.job_status = 2
    job_task_ref.job_state = job.state
    job_task_ref.worker_name = self.request.hostname
    db.session.add(job_task_ref)
    db.session.commit()
    task = db.session.query(Task).filter(Task.id == job_task_ref.task_id).first()
    task.start_time = job_task_ref.run_time
    task.state = 2
    db.session.add(task)
    db.session.commit()
    domain, scheme, path, cookie = get_task_domain(task.target)
    start_url = '%s://%s%s' % (scheme, domain, path)
    # # GET URL DATA FROM SPIDER_API
    # if spider_exec_id:
    #     get_url_data(spider_exec_id, task_id, domain)
    # start scan_spider
    if spider_flag:
        custom_headers = {
            'Host': domain,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0',
            'Accept-Encoding': 'gzip,deflate,sdch',
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Referer": start_url,
            'Cookie': cookie if cookie else ''
        }
        # from common.sql_orm import DBSession
        from common.spider_models import ScanSpiderUrl
        # db_session = DBSession()
        try:
            db.session.query(ScanSpiderUrl).filter(ScanSpiderUrl.task_id == task_id).delete()
            db.session.commit()
            spider_timeout = SPIDER_LIMIT_TIME.get(task.web_scan_policy, 1800)
            # 爬虫动态模式，快速扫描，只进行静态爬虫
            dynamic_parse = False if task.web_scan_policy == 511 else True
            spider = Spider(concurrent_num=2, depth=50, max_url_num=1000, crawler_mode=1, dynamic_parse=dynamic_parse,
                            spider_timeout=spider_timeout,custom_headers=custom_headers, login_dict=None,
                            scan_task_id=task_id)

            spider.feed_url(start_url)
            spider.start()
        except Exception, e:
            logger.error(e)
        try:
            # copy the urls to the table spider_url from scan_spider_url
            db.session.query(SpiderUrl).filter(SpiderUrl.task_id == task_id).delete()
            db.session.commit()
            urls = db.session.query(ScanSpiderUrl).filter(ScanSpiderUrl.task_id == task_id).all()
            if not urls:
                try:
                    spider_timeout = SPIDER_LIMIT_TIME.get(task.web_scan_policy, 1800)
                    dynamic_parse = False if task.web_scan_policy == 511 else True
                    spider = Spider(concurrent_num=2, depth=50, max_url_num=1000, crawler_mode=1, dynamic_parse=dynamic_parse,
                                    spider_timeout=spider_timeout,custom_headers=custom_headers, login_dict=None,
                                    scan_task_id=task_id)

                    spider.feed_url(start_url)
                    spider.start()
                except Exception, e:
                    logger.error(e)
                urls = db.session.query(ScanSpiderUrl).filter(ScanSpiderUrl.task_id == task_id).all()
            for s_url in urls:
                # print s_url.url, s_url.params, s_url.method, s_url.refer
                url = s_url.url
                params = s_url.params
                refer = s_url.refer if s_url.refer else start_url
                if 'GET' == s_url.method.upper():
                    url_split = url.split('?', 1)
                    url = url_split[0]
                    if len(url_split) > 1:
                        params = url_split[1]
                spider_url = SpiderUrl(task_id, url, params=params, method=s_url.method, refer=refer)
                db.session.add(spider_url)
                db.session.commit()
            # db_session.close()

            # copy the other_urls to the table spider_url_other from scan_spider_url_other
            db.session.query(SpiderUrlOther).filter(SpiderUrlOther.task_id == task_id).delete()
            db.session.commit()
            urls = db.session.query(ScanSpiderUrlOther.url, ScanSpiderUrlOther.refer, ScanSpiderUrlOther.type ).filter(ScanSpiderUrlOther.task_id == task_id).all()
            for s_url in urls:
                spider_url = SpiderUrlOther(task_id=task_id, url=s_url[0], refer=s_url[1], type=s_url[2])
                db.session.add(spider_url)
                db.session.commit()

        except Exception, e:
            logger.error(e)

    web_scan_engine = WebScanEngine(task_id, action)
    web_scan_engine.run()
    print 'finish_run_engine'
    job_task_ref.job_state = job.status
    job_task_ref.job_status = 3
    job_task_ref.end_time = datetime.now()
    db.session.add(job_task_ref)
    db.session.commit()
    task = db.session.query(Task).filter(Task.id == job_task_ref.task_id).first()
    task.end_time = job_task_ref.end_time
    task.state = 3
    db.session.add(task)
    db.session.commit()
    job_rep = run_report.apply_async(args=[task_id, job_id], countdown=5)
    # 生成全网态势报告数据并推送
    patch_task = db.session.query(PatchTask).filter(PatchTask.task_id == task_id, PatchTask.notify_state == 0).first()
    if patch_task:
        try:
            patch_rep = db.session.query(PatchReport).filter(PatchReport.patch_no == patch_task.patch_no).first()
            patch_no = patch_task.patch_no
            if not patch_rep:
                patch_rep = PatchReport(patch_no=patch_no)
            logger.debug("扫描任务task_id:%s,job_id:%s开始生成全网态势数据" % (task_id, job_id))
            rep_dict, task_rep_dict, domain = patch_rep.gen_rep(task_id)
            sort_rep_dict = deepcopy(rep_dict)
            post_data_dict = _sort_patch_rep(patch_no, sort_rep_dict)
            patch_rep.rep_json = json.dumps(rep_dict)
            patch_rep.task_ids += ',%s' % str(task_id)
            patch_rep.data_rep_json = json.dumps(post_data_dict)
            db.session.add(patch_rep)
            db.session.commit()
            # # 推送数据 rep_dict
            # notify_state, notify_msg = send_patch_rep(patch_task.patch_no, rep_dict)
            # # 推送数据 task_rep_json
            # notify_state, notify_msg = send_over_view_rep(patch_task.patch_no, task_rep_dict)
            task_post_data = {
                "patch_no": patch_no,
                "domain": task_rep_dict.keys()[0],
                "data": task_rep_dict.values()[0]
            }
            patch_task.task_rep_json = json.dumps(task_rep_dict)
            patch_task.data_rep_json = json.dumps(task_post_data)
            patch_task.domain = domain
            db.session.add(patch_task)
            db.session.commit()
            logger.debug("扫描任务task_id:%s,job_id:%s, patch_no:%s生成全网态势数据" % (task_id, job_id, patch_no))
            # 通知全网态势平台，扫描任务已完成，数据已生成
            logger.debug("扫描任务task_id:%s,job_id:%s, patch_no:%s通知态势感知平台" % (task_id, job_id, patch_no))
            notify_state, resp_str = notify_tsgz_task(patch_no, domain)
            patch_task.notify_state = notify_state
            patch_task.notify_msg = resp_str
            patch_task.notify_time = datetime.now()
            db.session.add(patch_task)
            db.session.commit()
        except Exception, e:
            logger.error(e)
    return {'current': 100, 'total': 100, 'status': 3, 'result': 100}


@celery.task(bind=True)
def run_report(self, task_id, job_id):
    try:
        logger.debug("扫描任务task_id:%s,job_id:%s执行报告生成任务  开始" % (task_id, job_id))
        rep = Report()
        report_id = rep.storage(task_id, job_id)
        if not report_id:
            rep.checkPdfExists()
        logger.debug("扫描任务task_id:%s,job_id:%s执行报告生成任务  结束" % (task_id, job_id))
    except Exception, e:
        logger.debug(e)
        logger.debug("扫描任务task_id:%s,job_id:%s执行报告生成任务  异常" % (task_id, job_id))


class TestCron:
    def __init__(self, str1, str2):
        self.str1 = str1
        self.str2 = str2

    def run(self, job):
        print job.id, job.state
        print self.str1, self.str2


# 队列中取消JOB 及子任务
def revoke_job(job_id):
    # job = run_spider.AsyncResult(job_id)
    # job.revoke()
    try:
        celery.control.revoke(job_id)
        job_child_list = db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.parent_id == job_id).all()
        if len(job_child_list) > 0:
            for job_child in job_child_list:
                celery.control.revoke(job_child.job_id)
        return True
    except Exception, e:
        logger.error(e)
        return False


# 数据库中删除JOB 及子任务
def del_job_db(job_id):
    try:
        db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.parent_id == job_id).delete()
        db.session.query(ApJobsTaskRef).filter(ApJobsTaskRef.job_id == job_id).delete()
        db.session.commit()
        return True
    except Exception, e:
        print e
        logger.error(e)
        return False


def job_status(job_id):
    job = run_engine.AsyncResult(job_id)

    if job.state == 'PENDING':
        # job did not start yet
        response = {
            'state': job.state,
            'current': 0,
            'total': 1,
            'status': 1
        }
    elif job.state != 'FAILURE':
        response = {
            'state': job.state,
            'current': job.info.get('current', 0),
            'total': job.info.get('total', 1),
            'status': job.info.get('status', 2)
        }
        if 'result' in job.info:
            response['result'] = job.info['result']
    else:
        # something went wrong in the background job
        response = {
            'state': job.state,
            'current': 1,
            'total': 1,
            'status': 5,
            'exception': str(job.info),  # this is the exception raised
        }
    return jsonify(response)


def get_url_data(execute_id, task_id, domain):
    url = '%s/execute/urlsbyid/%s' % (SPIDER_URL, execute_id)
    header = {'token': SPIDER_TOKEN, 'Content-Type': 'application/x-www-form-urlencoded'}
    ignore_ext = ['js', 'css', 'png', 'jpg', 'gif', 'bmp', 'svg', 'exif', 'jpeg', 'exe', 'rar', 'zip']
    http = httplib2.Http()
    for _i in xrange(3):
        try:
            res, content = http.request(url, 'GET', headers=header)
            con = json.loads(content)
            if res.get('status') == '200' and con.get('status') == 'ok':
                data_list = con.get('data')
                break
        except Exception, e:
            data_list = None
            continue
    domain_dirs = set()
    if data_list:
        try:
            db.session.query(SpiderUrl).filter(SpiderUrl.task_id == task_id).delete()

            url_elements_list = []
            for data in data_list:

                url = data.get('url')
                print url
                # url_parse = urlparse.urlparse(url)
                url_ext = os.path.splitext(urlparse.urlsplit(url).path)[-1][1:]
                if url_ext in ignore_ext:
                    continue
                method = data.get('method')
                post = data.get('post')
                query = data.get('query')
                params = post
                if 'GET' == method:
                    url = url.split('?')[0]
                    params = query
                    # 针对get的url去重（因为post的参数类型暂时不支持去重)
                    url_elements = (url_dir, url_ext, params_keys) = get_url_element(url, params, method)
                    if url_dir:
                        domain_dirs.add(url_dir)
                    if url_elements in url_elements_list:
                        print url_elements
                        continue
                    else:
                        url_elements_list.append(url_elements)
                http_code = data.get('http_code')
                refer = data.get('referer')
                url_domain = urlparse.urlparse(url).netloc
                url_domain = url_domain.split(':')[0]
                if domain.find(url_domain) == -1 and url_domain.find(domain) == -1 and \
                                domain.find(url_domain.split('.', 1)[1]) == -1:
                    spider_url = SpiderUrlOther(task_id, url, params=params, method=method, refer=refer)
                else:
                    spider_url = SpiderUrl(task_id, url, params=params, method=method, refer=refer)
                db.session.add(spider_url)
                print 1111111111
            db.session.commit()

        except Exception, e:
            logger.error(e)
    if domain_dirs:
        spider_job = db.session.query(SpiderJob).filter(SpiderJob.task_id == task_id).first()
        spider_job.domain_dirs = domain_dirs
        db.session.add(spider_job)
        db.session.commit()


def get_task_domain(target):
    try:
        target = json.loads(target)[0]
        domain = target.get('domain')
        scheme = target.get('scheme')
        path = target.get('path')
        cookie = target.get('cookie')
        return domain, scheme, path, cookie
    except Exception, e:
        return ''


if __name__ == '__main__':
    get_url_data(1468, 819)
