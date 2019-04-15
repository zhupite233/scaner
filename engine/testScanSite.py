# -*- coding:UTF-8 -*-

import os
import sys
from ScanSite_lidq import *
from SearchSite import *
from engineConfig import SCANER_TEMP_DIR
from engine_utils.common import *

taskId = 342
assetTaskId = 0
taskCnf = {
    'target' : '',
    'spider_type':2,
    'asset_task_id':0,
    'spider_enable':1,
    'web_scan_timeout':'',
    'web_scan_timeout':3600,
    'spider_url_count':2000,
    'web_search_site_state':1,
    'web_search_site_timeout':30,
    'vulList':[],
    'vulDict':[],
}
searchSite = SearchSite(taskId, taskCnf)
searchSite.start()
searchSite.join()

print "siteQueue::::::" + str(siteQueue.qsize())

threadLock = threading.Lock()
scanSite = ScanSite(taskId, assetTaskId, taskCnf, threadLock)
scanSite.start()
scanSite.join()

