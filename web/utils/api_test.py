# --*-- coding: utf-8 --*--
import json
from datetime import datetime

import requests

header = {
    # "Host": ob['domain'],
    # "Connection": "keep-alive",
    # "Pragma": "no-cache",
    # "Cache-Control": "no-cache",
    # "Referer": item['refer'],
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
    # "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    # "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
    # "Accept-Encoding": "gzip, deflate",
    # # "Cookie": ob.get('cookie')
}


def _test_add_task(task_name, urls, run_time=None, run_now=True, source_ip=None, patch_no=None, policy=511,
                   scan_key='33247100b6de11e698f9005056c00008',
                   multiple_task=True):
    post_data = {'task_name': task_name, 'urls': urls, 'run_now': run_now, 'scan_key': scan_key, 'source_ip': source_ip,
                 'patch_no': patch_no,'multiple_task': multiple_task, 'task_policy': policy, 'run_now': 509, "run_time": run_time}

    add_task_url = "http://scan.yundun.com/api/v1/tasks"
    resp = requests.post(add_task_url, post_data, headers=header)

    print resp
    res = resp.json()
    print res

def _get_task(scan_key='33247100b6de11e698f9005056c00008'):

    data = {'job_id': "b77059e0-98e1-47ff-9d9f-bc059cb7fa25", 'scan_key': scan_key}
    add_task_url = "http://192.168.3.86/api/v1/tasks/progress"
    # resp = requests.get(add_task_url, data)
    resp = requests.post(add_task_url, data, headers=header)
    # print resp.__dict__
    print resp.json()

def _get_task_patch(scan_key='33247100b6de11e698f9005056c00008'):
    job_id = {"jobs": ["b77059e0-98e1-47ff-9d9f-bc059cb7fa25"]}
    data = {'job_id': json.dumps(job_id), 'scan_key': scan_key}
    add_task_url = "http://127.0.0.1:8091/api/v1/tasks/progress2"
    # resp = requests.get(add_task_url, data)
    resp = requests.post(add_task_url, data, headers=header)
    # print resp.__dict__
    print resp.json()


def _get_report(task_id):
    get_report_url = "http://192.168.3.85:8090/api/v1/reports/" + str(task_id)
    data = {'scan_key': '6912eac080a711e698e4005056c00008'}
    resp = requests.get(get_report_url, data)
    print resp
    print resp.json()


def _get_reports():
    get_report_url = "http://192.168.5.111:8091/api/v1/reports"
    data = {'scan_key': '6912eac080a711e698e4005056c00008'}
    resp = requests.get(get_report_url, data)
    print resp
    print resp.json()


def _re_start_job():
    add_task_url = "https://scan.yundun.com/scheduler_job"
    for task in [1209,

                 1248]:
        data = {'job_id': task, 'operation': 'restart', 'scan_key': '33247100b6de11e698f9005056c00008'}
        resp = requests.post(add_task_url, data, headers=header)
        print resp
        print resp.json()


def spider_notify_api(spider_task_id, exe_id):
    url = 'http://192.168.5.117:8091/api/v1/spider/notify'
    data = {'task_id': spider_task_id, 'execute_id': exe_id}
    resp = requests.post(url, json.dumps(data), headers=header)
    print resp.content
    print resp.headers


if __name__ == '__main__':
    # task_name = 'mcj_compare'
    _get_task()
    # _get_report(136)
    # _get_reports()
    # from datetime import datetime
    # _test_add_task('test_tsgz_rep', patch_no='TSGZ500100928120170824140024J3ll', urls='http://www.buqiuwenda.com/', run_time=datetime.now())
    # tasks = (('219.153.9.72', 'http://www.cqjkq.gov.cn/')
    #          )
    # task_name = '重庆南岸区重点单位名单1-50'
    # for source_ip, url in tasks:
    #     _test_add_task(task_name, source_ip=source_ip, urls=url, run_time=datetime.now())
    #     # spider_notify_api(244,6396)
