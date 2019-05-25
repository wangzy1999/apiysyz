#!/usr/bin/env python
# coding: utf-8

"""
云上扬州定制开发API接口
依赖web.py
https://github.com/webpy/webpy
"""

from __future__ import absolute_import, print_function

import json
import os
import urllib
import urllib2
import urlparse
import socket
import datetime
import traceback
import tempfile
import cookielib
import pprint
import logging
import base64

from transformData import get_content_ids, transformData, get_weakness_ids, check_time, find_earliest
from dataHandle import connect_db, creat_table, sql_insert, show_data, close_db, total, sql_select
from logHandel import save_log

import web
from web import webapi
from web import template
from web.debugerror import debugerror
from web.application import application
from web.session import Session
from web.session import DiskStore
from web.httpserver import StaticMiddleware

def _decode_messgae(res):
    jdata = json.loads(res)
    return jdata['message']

class BaseHandler(object):

    def __init__(self):
        self.render = web.config._render
        self.session = web.config._session
        self.opener = web.config._opener

    def POST(self):
        raise webapi.NoMethod()

    def GET(self):
        raise webapi.NoMethod()

    def API(self, url, data):
        """ 
        url 需要请求的URL
        data 请求附加的数据 (注意不要有特殊的数据类型否则dumps失败)
        """
        src_data = {'parameter': json.dumps(data)}
        data = urllib.urlencode(src_data)
        req = urllib2.Request(url, data=data)

        # Django 版本升级到 1.5 后需要加这个 请求头否则无法正确处理数据
        req.add_header('CONTENT_TYPE','application/x-www-form-urlencoded')
        req.add_header('Accept', 'application/json')
        resp = None
        try:
            resp = self.opener.open(req)
        except Exception,e:
            traceback.print_exc(e)
        return req, resp

    def RenderJSON(self, req, resp):
        pass

    def JSON(self, data):
        webapi.header('Content-type','application/json', True)
        return json.dumps(data)

class HomePage(BaseHandler):
    def GET(self):
        return self.render.index()

class RevScanData(BaseHandler):
    '''
    接受扫描结果并入库：event.db -> EVENT
    '''
    def POST(self):
        data = webapi.rawinput('POST')
        decode = None
        try:
            decode = json.loads(data.parameter)
        except Exception, e:
            print(e.message)
            print(repr(data))
            return u'{"code":0,"message":"decode fail"}'
        if decode['total'] > 0:
            if decode['module_type'] == 'weakness' or decode['module_type'] == 'content':          
                for i in decode['values']:
                    data_site = decode['site']
                    happen_time = i['created_at']
                    data_value = json.dumps(i, indent=2)
                    data_type = decode['module_type']
                    data_state = "unknown"
                    if data_value != None and len(data_value)>3:
                        push_time = ''
                        save_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        sql_insert(data_site, data_value, data_type, data_state, save_time, push_time, happen_time)
                        save_log('DEBUG', data_site + 'insert into database successful')
        return self.JSON({'code': 0, 'message': 'ok'})

class ShowData(BaseHandler):
    #展示未推送的数据
    def GET(self):
        web.header("Access-Control-Allow-Origin", "*")
        get_dict = webapi.rawinput('GET')
        page = int(get_dict.get('page', None))
        size = int(get_dict.get('size', None))
        state = get_dict.get('state', None)
        if state:
            datas = show_data(state) #按类别筛选的数据
        else:
            state = 'all'
            datas = show_data(state) #所有未推送的数据
        result = {}
        if not datas == None:
            result['total'] = len(datas)
        values = []
        start = (page-1)*20
        end = start + size
        #如果数据不够
        if len(datas)<size or len(datas)<end:
            for i in datas:
                data = {}
                data['id'] = i[0]
                data['site'] = i[1]
                data['value'] = i[2]
                data['type'] = i[3]
                data['state'] = i[4]
                data['save_time'] = i[5]
                data['push_time'] = i[6]
                data['happen_time'] = i[7]
                values.append(data)
        else:
            for i in datas[start:end]:
                data = {}
                data['id'] = i[0]
                data['site'] = i[1]
                data['value'] = i[2]
                data['type'] = i[3]
                data['state'] = i[4]
                data['save_time'] = i[5]
                data['push_time'] = i[6]
                data['happen_time'] = i[7]
                values.append(data)
        result['values'] = values
        return self.JSON(result)

class id_for_Update(BaseHandler):
    '''
    #根据ID筛选改变状态
    '''
    def POST(self):
        web.header("Access-Control-Allow-Origin", "*")
        data = web.data()
        data = json.loads(data)
        print (data)
        action = data['action']
        ids = data['ids']
        if action == None or ids == None:
            return self.JSON({'code':'1:lack of data'})
        elif ids == -1:
            con, cur = connect_db()
            cur.execute("update EVENT set state=?",(action,))
            con.commit()
            save_log('INFO', 'all data state change to' + action)
            close_db(con,cur)
        elif ids != []:
            con, cur = connect_db()
            for id in ids:
                cur.execute("update EVENT set state=? where id=?",(action, id,))
            con.commit()
            save_log('DEBUG', 'data state change to {} where id is{}'.format(action, id))
            close_db(con,cur)
        return self.JSON({'code':'0'})

class state_for_Update(BaseHandler):
    #根据状态筛选改变状态
    def POST(self):
        web.header("Access-Control-Allow-Origin", "*")
        rawdata = web.data()
        rawdata = json.loads(rawdata)
        state = rawdata.get('state', None)
        action = rawdata.get('action', None)
        if action == None or state == None:
            return self.JSON({'code':'1:lack of data'})
        else:
            con, cur = connect_db()
            cur.execute("update EVENT set state=? where state=?", (action, state,))
            con.commit()
            save_log('DEBUG', 'all data where state is {} change to {}'.format(state, action))
            close_db(con,cur)
            return self.JSON({'code':'0'})

class trans_content(BaseHandler):
    '''
    调用该接口获取安全事件数据
    '''
    def GET(self):
        web.header("Access-Control-Allow-Origin", "*")
        get_dict = web.input()
        token = get_dict.get('token', None)
        start_time = get_dict.get('start_time', '0')
        end_time = get_dict.get('end_time', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        con,cur = connect_db()
        cur.execute('select token from token')
        real_token = cur.fetchall()[0][0]
        if token == real_token:
            save_log('INFO', 'token success ,prepare for data')
            push_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ids = get_content_ids()
            con,cur = connect_db()
            value = []
            for i in ids:
                data = sql_select(i[0])
                happen_time = data[7]
                if check_time(start_time, end_time, happen_time):
                    data = transformData(int(i[0]))
                    value.append(data)
                    cur.execute("update EVENT set state=? where id=?", ("push", int(i[0])))
                    cur.execute("update EVENT set push_time=? where id=?", (push_time, int(i[0])))
            con.commit()
            close_db(con, cur)
            save_log('DEBUG', 'content database changed')
            save_log('INFO', 'generate content data success')
            response = {"status":200, "errMsg":'success', "data" : value}
            save_log('INFO', 'sending content data...')
            return self.JSON(response)
        else:
            save_log('INFO', 'failed with invalid token')
            web.header("status_code", "400")
            response = {"status":400, "errMsg":'token is invalid'}
            return self.JSON(response)

class trans_weakness(BaseHandler):
    '''
    调用该接口获取漏洞数据
    '''
    def GET(self):
        web.header("Access-Control-Allow-Origin", "*")
        get_dict = web.input()
        token = get_dict.get('token', None)
        start_time = get_dict.get('start_time', '0')
        end_time = get_dict.get('end_time', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        con,cur = connect_db()
        cur.execute('select token from token')
        real_token = cur.fetchall()[0][0]
        if token == real_token:
            save_log('INFO', 'token success, prepare for data')
            push_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ids = get_weakness_ids()
            con,cur = connect_db()
            value = []
            for i in ids:
                data = sql_select(i[0])
                happen_time = data[7]
                if check_time(start_time, end_time, happen_time):
                    data = transformData(i[0])
                    value.append(data)
                    cur.execute("update EVENT set state=? where id=?", ('push', int(i[0]),))
                    cur.execute("update EVENT set push_time=? where id=?", (push_time, int(i[0]),))
            con.commit()
            close_db(con, cur)
            save_log('DEBUG', 'weakness database changed')
            save_log('INFO', 'generate weakness data successful')
            response = {"status":200, "errMsg":'success', "data" : value}
            save_log('INFO', 'send weakness data...')
            return self.JSON(response)
        else:
            save_log('INFO', 'failed with invalide token')
            web.header("status_code", "400")
            response = {"status":400, "errMsg":'token is invalid'}
            return self.JSON(response)

class getToken(BaseHandler):
    #获取token
    def GET(self):
        get_dict = web.input()
        userName = get_dict.userName
        password = get_dict.get('password', None)
        password = base64.b64decode(password)
        con, cur = connect_db()
        cur.execute("select token from token where username='wnagnn'")
        token = cur.fetchall()[0][0] #数据库中对应的token
        cur.execute("select password from token where username='wnagnn'")
        pwd = cur.fetchall()[0][0] #数据库中对应的密码
        close_db(con, cur)
        if userName == 'wnagnn':
            if password == pwd:
                result = {"status":200, "token":token}
            else:
                result = {"status":400, "errMsg":"password is error"}
        else:
            result = {"status":400, "errMsg":"userName is error"}
        return self.JSON(result)

class getTimeInterval(BaseHandler):
    def GET(self):
        est_time = find_earliest() if find_earliest() else ''
        return self.JSON({"earliest_happen_time":est_time})

def init_ds():
    root = tempfile.mkdtemp()
    s = DiskStore(root)
    return s

def init_opener(cookies):
    opener = urllib2.build_opener(urllib2.HTTPHandler(),
                                urllib2.HTTPCookieProcessor(cookies))
    return opener

def main():
    urls = (
        '/', 'HomePage',
        '/push/rev', 'RevScanData',
        '/items', 'ShowData',
        '/idact', 'id_for_Update',
        '/stact', 'state_for_Update',
        '/api/logincy', 'getToken',
        '/api/content', 'trans_content',
        '/api/weakness', 'trans_weakness',
        '/api/getTimeInterval', 'getTimeInterval')
    app = application(urls, globals())
    app.internalerror = debugerror

    if web.config.get('_session') is None:
        ds = init_ds()
        session = Session(app, ds)
        web.config._session = session

    if web.config.get('_render') is None:
        render = template.render('templates',
                                    globals={'context': session})
        web.config._render = render

    if web.config.get('_cookies') is None:
        cookies = cookielib.CookieJar()
        web.config._cookies = cookies

    if web.config.get('_opener') is None:
        opener = init_opener(web.config._cookies)
        web.config._opener = opener

    if web.config.get('_rev') is None:
        web.config._rev = {}

    app.wsgifunc(StaticMiddleware)
    return app

if __name__ == '__main__':
    socket.setdefaulttimeout(20)
    creat_table()
    app = main()
    app.run()
