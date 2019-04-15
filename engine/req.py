import urllib2
import httplib2

url="http://www.ifeng.com"
method="GET"
#req = urllib2.Request(url=url, data="", headers={})
#req = urllib2.Request(url=url, data="")
#request = urllib2.Request(url=url)
#response = urllib2.urlopen(req)
#print request.get_method()
#print request.header_items()

#print response.info().items()                 #response headers
#print response.getcode()
#print response.geturl()
#print response.read()

def request(url=url, method="GET", body="", headers={}, redirections=5, timeout=30):
    try:
        http = httplib2.Http(timeout=timeout)
        response, content = http.request(url, method, body=body, headers=headers, redirections=redirections)
        httpCode = response.status
        headerDict = {}
        for row in response.items():
           headerDict[row[0]] = row[1]
        result = {"httpCode":response.status, "headers":headerDict, "body":content, "error":""}
    except Exception, e:
        result = {"httpCode":0, "headers":{}, "body":"", "error":e.message}
    return result

print request(url="http://www.ifeng.co", timeout=3)


