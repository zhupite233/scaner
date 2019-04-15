# --*-- coding: utf-8 --*--
from datetime import datetime

from web import db
from web.models.task import Sites, Task
from web.models.web_policy_db import WebVulPolicyRef


def task_progress(task_id):
    task_site = db.session.query(Sites).filter(Sites.task_id == task_id).all()
    task = db.session.query(Task).filter(Task.id == task_id).first()
    if task.start_time >= datetime.now():
        print task.start_time
        response = {
            'task_id': task_id,
            'state': '未开始'.decode('utf-8'),
            'current': 0,
            'total': 100,
            'status': 0
        }
        return response
    sites_count = len(task_site)
    if sites_count == 0:
        response = {
            'task_id': task_id,
            'state': '扫描准备中'.decode('utf-8'),
            'current': 0,
            'total': 100,
            'status': 1
        }
    else:
        current = 0
        for site in task_site:

            if site.state == 1:
                current += 100 * (1.0 / sites_count)

            elif site.spider_state != 1:
                if site.start_time is None:
                    pass
                else:
                    run_seconds = (datetime.now()-site.start_time).seconds
                    current_spider = (run_seconds/600)*10
                    if current_spider > 10:
                        current_spider = 10
                    current += current_spider * (1.0/sites_count)

            else:
                progress = site.progress.split('|')
                policy_script_count = db.session.query(WebVulPolicyRef).filter(WebVulPolicyRef.policy_id == site.policy).count()
                current_scan = 10+90*len(progress)/policy_script_count
                if current_scan >= 97:
                    current_scan = 97
                current += (current_scan * (1.0/sites_count))

        if task.state == 3:
            response = {
                'task_id': task_id,
                'state': '扫描完成'.decode('utf-8'),
                'current': 100,
                'total': 100,
                'status': 3
            }
        else:
            response = {
                    'task_id': task_id,
                    'state': '扫描进行中'.decode('utf-8'),
                    'current': current,
                    'total': 100,
                    'status': 2
            }
    return response