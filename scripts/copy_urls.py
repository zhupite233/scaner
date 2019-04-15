# coding utf-8
from common.sql_orm import DBSession
from common.spider_models import ScanSpiderUrl
from web import db
from web.models.task import SpiderUrl


def copy_urls(task_id):
    db_session = DBSession()
    db.session.query(SpiderUrl).filter(SpiderUrl.task_id == task_id).delete()

    urls = db_session.query(ScanSpiderUrl).filter(ScanSpiderUrl.task_id == task_id).all()
    for s_url in urls:
        # print s_url.url, s_url.params, s_url.method, s_url.refer
        url = s_url.url
        params = s_url.params
        if 'GET' == s_url.method.upper():
            url_split = url.split('?', 1)
            url = url_split[0]
            if len(url_split) > 1:
                params = url_split[1]
        spider_url = SpiderUrl(task_id, url, params=params, method=s_url.method, refer=s_url.refer)
        db.session.add(spider_url)
        db.session.commit()
    db_session.close()

if __name__ == '__main__':
    copy_urls(895)