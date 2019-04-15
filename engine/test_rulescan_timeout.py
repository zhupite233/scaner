# --*-- coding: utf-8 --*--
import time
from engine.engine_lib.HttpRequest import HttpRequest

timeout_count = 0
for i in range(20):
    if timeout_count>80:
        break
    else:
        n = timeout_count/10 +1
        timeout = 10/n
    http = HttpRequest({'timeout': timeout, 'follow_redirects':False})
    try:
        for j in range(2):
            url = 'http://192.168.11.11:8089'
            try:
                t1 = time.time()
                res, content = http.request(url, 'GET', headers=None)
                print 2222222222222
            except Exception,e:
                timeout_count += 1
                t2 = time.time()
                print 'timeout_count:::::::', timeout_count, t2-t1
                pass
    except Exception,e:
        print 111111111