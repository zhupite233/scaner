from common.spider_models import ScanSpiderUrl

from web import db

urls = db.session.query(ScanSpiderUrl).filter(ScanSpiderUrl.task_id==1293).all()
for url in urls:
    print url


