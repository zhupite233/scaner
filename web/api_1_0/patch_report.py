# --*-- coding: utf-8 --*--
from flask import jsonify
import json
import requests
from config import PATCH_REP_URL
from urlparse import urlparse
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
           "Content-Type": "application/json; charset=utf-8"}

get_headers = {
    "Host": urlparse(PATCH_REP_URL).netloc,
    "Connection": "keep-alive",
    # "Pragma": "no-cache",
     "Cache-Control": "no-cache",
    # "Referer": "",
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
     "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
    "Accept-Encoding": "gzip, deflate",
    # # "Cookie": ob.get('cookie')
}


def notify_tsgz_task(patch_no, domain):
    notify_state = 0
    notify_url = PATCH_REP_URL + '/tsgz_domain_scan_url'
    data = {'patch_no': patch_no, 'domain': domain}
    try:
        resp = requests.get(notify_url, data, headers=get_headers)
        resp_str = 'http_code: %s, headers: %s, content: %s' % (str(resp.status_code), str(resp.headers), str(resp.content))
        notify_state = 1
    except Exception, e:
        resp_str = str(e)
    return notify_state, resp_str


def _sort_patch_rep(patch_no, sort_rep_dict):
    ranking_dict = sort_rep_dict.get('ranking')
    dis_dict = sort_rep_dict.get('distribute')

    l_ranking = []
    r_list = sorted(ranking_dict.iteritems(), key=lambda e: e[1]['count'], reverse=True)
    c = 0
    for ele in r_list:
        if c >= 20:
            break
        ele[1]['type'] = ele[0]
        l_ranking.append(ele[1])
        c += 1
    sort_rep_dict['ranking'] = l_ranking

    l_dis = []
    d_list = sorted(dis_dict.iteritems(), key=lambda e: (e[1]['HIGH'], e[1]['MED'], e[1]['LOW']), reverse=True)
    cc = 0
    for element in d_list:
        if cc >= 10:
            break
        element[1]['domain'] = element[0]
        l_dis.append(element[1])
        cc += 1
    sort_rep_dict['distribute'] = l_dis
    post_data = {
        "patch_no": patch_no,
        "data": sort_rep_dict
    }
    return post_data


def send_patch_rep(patch_no, rep_dict):
     #{"ranking": {vul_family_name: {"count": 200, "url_count": 150}},
     #    "distribute": {www.baidu.com: {"HIGH": 5, "MED": 3, "LOW": 6}}
     # }

    notify_state = 2
    notify_msg = ''

    post_data = _sort_patch_rep(patch_no, rep_dict)
    post_str = json.dumps(post_data)
    url = PATCH_REP_URL
    resp = requests.post(url + '/tsgz_scan_loophole_count', data=post_str, headers=headers)
    print resp.headers
    if resp:
        con = resp.content
        notify_msg = con
        if resp.status_code == 200 and con == 'ok':
            notify_state = 1
            # notify_msg = con.get('msg')
    return notify_state, notify_msg


def send_over_view_rep(patch_no, rep_dict):
    notify_state = 2
    notify_msg = ''
    post_data = {
        "patch_no": patch_no,
        "domain": rep_dict.keys()[0],
        "data": rep_dict.values()[0]
    }
    url = PATCH_REP_URL
    try:
        post_str = json.dumps(post_data)
        resp = requests.post(url + '/tsgz_scan_loophole_detail', data=post_str, headers=headers)
        if resp:
            con = resp.content
            resp_str = 'http_code: %s, headers: %s, content: %s' % (str(resp.status_code), str(resp.headers), str(resp.content))
            notify_msg = resp_str
            if resp.status_code == 200 and con == 'ok':
                notify_state = 1
                # notify_msg = con.get('msg')
    except Exception, e:
        notify_msg = str(e)
    return notify_state, notify_msg


if __name__ == '__main__':
    patch_no = 'TSGZ500100928120170824140024J4jj'
    domain = 'demo.aisec.cn'
    print notify_tsgz_task(patch_no, domain)

