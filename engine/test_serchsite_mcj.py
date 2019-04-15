# --*-- coding:utf-8 --*--
from SearchSite import SearchSite
from db.MysqlDao import MysqlDao
dao = MysqlDao()
task_id = 739
task_cnf = dao.getTaskData(task_id)
th = SearchSite(task_id, task_cnf)
th.start()
th.join()