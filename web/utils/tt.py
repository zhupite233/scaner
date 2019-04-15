# --*-- coding:utf-8 --*--
import MySQLdb
import MySQLdb.cursors
sql = "SELECT task_id,job_id FROM ap_jobs_task_ref WHERE run_time < '2017-03-15 15:00:00' and task_id>=1208 and task_id<=1248"
db = MySQLdb.connect('115.238.233.206', 'ydscan', 'Flzx3qcYsyhl9t', 'scan')
cursor = db.cursor()
cursor.execute(sql)
task_list = cursor.fetchall()
for task in task_list:
    print task[0], task[1]
    update_sql = "update ap_jobs_task_ref SET job_id='%s' where task_id=%s and run_time > '2017-03-15 15:00:00' " \
                 "and task_id>=1208 and task_id<=1248" % (task[1], task[0])
    update_sql2 = "update report SET job_id='%s' where task_id=%s and task_id>=1208 and task_id<=1248" % (task[1], task[0])
    up_cursor = db.cursor()
    up_cursor.execute(update_sql)
    up_cursor.execute(update_sql2)
    db.commit()
