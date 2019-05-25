#!/usr/bin/env python
# coding: utf-8
'''
根据id从数据库中筛选数据
并转换到客户要求的形式
'''
from dataHandle import sql_select, connect_db, close_db
from logHandel import save_log
import json

def get_content_ids():
    con, cur = connect_db()
    cur.execute("SELECT ID FROM EVENT WHERE state='exist' AND type='content'")
    ids = cur.fetchall()
    close_db(con, cur)
    return ids

def get_weakness_ids():
    con, cur = connect_db()
    cur.execute("SELECT ID FROM EVENT WHERE state='exist' AND type='weakness'")
    ids = cur.fetchall()
    close_db(con, cur)
    return ids

def find_earliest():
	timelist = []
	con, cur = connect_db()
	cur.execute("SELECT happen_time FROM event")
	rawtimelist = cur.fetchall()
	close_db(con, cur)
	for i in rawtimelist:
		timelist.append(i[0])
	if len(timelist) >= 2:
		timelist.sort()
		return timelist[0]
	else:
		return timelist[0]


def check_time(start_time, end_time, happen_time):
	'''
	如果happen_time介于start_time和end_time之间 返回True
	'''
	start_time = start_time.replace('-','').replace(':','').replace(' ', '')
	end_time = end_time.replace('-','').replace(':','').replace(' ', '')
	happen_time = happen_time.replace('-','').replace(':','').replace(' ', '')
	return True if happen_time >= start_time and happen_time <= end_time else False

def transformData(id):
	save_log('DEBUG','transforming data whose id is {}'.format(id))
	data = sql_select(id)
	org_site = data[1]
	detail = json.loads(data[2])
	module_type = data[3]
	state = data[4]
	if module_type == 'weakness':
		result = {}
		result['vender_id'] = 2
		result['org_site'] = org_site
		result['url'] = detail['url']
		result['display_name'] = detail['value'].get('name', None)
		result['happen_time'] = detail['created_at']
		result['poc'] = detail['value']
		result['type'] = detail['value'].get('type', None)
		result['vul_id'] = detail['value'].get('vul_id', None)
		result['detail'] = detail['value'].get('detail', None)
		if state != 'push' :
			data = json.dumps(result, indent=2)
			return data
	elif module_type == 'content':
		result = {}
		result['vender_id'] = 2
		result['org_site'] = org_site
		result['id'] = id
		result['url'] = detail['url']
		result['happen_time'] = detail['created_at']
		result['poc'] = detail['value']
		type = detail.get('type', None)
		# TODO 4:身份证批量泄露 5:黑页 12:外链
		type = 2 if type == 'black_links' or type == 'black_link' else type
		type = 4 if type == 'email_address_disclosure' or type == 'email_address_disclosure_out' else type
		type = 6 if type.lower() == 'webshell' else type
		type = 7 if type == 'malscan' else type
		type = 8 if type == 'cryjack' else type
		type = 10 if type == 'keyword' else type
		type = 11 if type == 'broken_links' or type == 'broken_link' else type
		result['type'] = type
		if state != 'push':
			data = json.dumps(result, indent=2)
			return data
		else:
			save_log('DEBUG', 'data with id={} has been pushed, do not push again'.format(id))
			pass
