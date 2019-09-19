#!/usr/bin/python
# -*- coding: UTF-8 -*-

import MySQLdb

db = MySQLdb.connect("127.0.0.1", "root", "ahg8eeY8", "test", charset='utf8')

cursor = db.cursor()

cursor.execute("SELECT VERSION()")

data = cursor.fetchone()

print "Database version : %s " % data

cursor.execute("DROP TABLE IF EXISTS jige003")

sql = """CREATE TABLE jige003 (
         name  CHAR(20) NOT NULL,
         mail  CHAR(20),
         age INT
          )"""
cursor.execute(sql)

sql = """INSERT INTO jige003(name,
         mail, age)
         VALUES ('jige003', 'jige003@mial.com', 100)"""

try:
    cursor.execute(sql)
    db.commit()
except BaseException:
    db.rollback()

args = ("jige003", 100)
sql = "select * from jige003 where name = %s  and age = %s"
cursor.execute(sql, args)

db.close()
