#!/usr/bin/env python
# coding: utf-8

import sqlite3
import json


def connect_db():
	#connect content database
	con = sqlite3.connect('event.db')
	cur = con.cursor()
	return con, cur


def creat_table():
	con, cur = connect_db()
	try:
		cur.execute('CREATE TABLE EVENT (id integer primary key autoincrement, site text, value text, type text, state text, save_time text, push_time text, happen_time text)')
	except Exception:
		pass
	finally:
		con.commit()
		close_db(con, cur)


def sql_insert(site, value, module_type, state, save_time, push_time, happen_time):
	#insert data
	con, cur = connect_db()
	try:
		cur.execute("INSERT INTO EVENT (site, value, type, state, save_time, push_time, happen_time)VALUES(?,?,?,?,?,?,?)",
		            (site, value, module_type, state, save_time, push_time, happen_time))
		con.commit()
	except Exception, e:
		print e.message
	finally:
		close_db(con, cur)


def total():
	con, cur = connect_db()
	cur.execute('select count(id) from event')
	total = cur.fetchall()[0][0]
	close_db(con, cur)
	return total


def sql_select(id):
	con, cur = connect_db()
	cur.execute('select * from Event where id=?', (id,))
	data = cur.fetchall()
	close_db(con, cur)
	return data[0]


def show_data(state):
	con, cur = connect_db()
	if state == 'all':
		cur.execute("select *from EVENT")
		data = cur.fetchall()
	else:
		cur.execute("select *from EVENT where state=?",(state,))
		data = cur.fetchall()
	close_db(con,cur)
	return data

def close_db(con,cur):
	#close database
	cur.close()
	con.close()

