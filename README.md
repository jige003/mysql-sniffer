# mysql-sniffer
> mysql sniffer network traffic 

### 功能
* 支持handshake 协议解析
* 支持query 命令解析
* 支持预编译及参数解析

### Usage
```
Copyright by jige003

Usage:
    mysql-sniffer [-h] -i interface -p port
```

### 日志
> test_mysql 预编译查询测试
```
[*] sniffe on interface: lo
2019-09-19 15:54:45 127.0.0.1:3306-127.0.0.1:36102 [ greet handshake ] protocal: 10  version: 5.5.59 auth_plugin: mysql_native_password
2019-09-19 15:54:45 127.0.0.1:36102-127.0.0.1:3306 db: test user: root [ login handshake ] user: root  password: c4f0397eb321fa1f201c11f78fced470cae70a48 dbname: test client_auth_plugin: mysql_native_password
2019-09-19 15:54:45 127.0.0.1:36102-127.0.0.1:3306 db: test user: root [ stmt query ] select * from jige003 where name = ? and age = ?
2019-09-19 15:54:45 127.0.0.1:36102-127.0.0.1:3306 db: test user: root [ stmt exe params ] num_params: 2 params<0>: jige003 params<1>: 100
```

> x.py 正常query协议测试
```
[*] sniffe on interface: lo
2019-09-19 17:13:49 127.0.0.1:3306-127.0.0.1:36436 [ greet handshake ] protocal: 10  version: 5.5.59 auth_plugin: mysql_native_password
2019-09-19 17:13:49 127.0.0.1:36436-127.0.0.1:3306 db: test user: root [ login handshake ] user: root  password: 78993c4e01c9fc840f42cd7718c00084fd2d93a2 dbname: test client_auth_plugin: mysql_native_password
2019-09-19 17:13:49 127.0.0.1:36436-127.0.0.1:3306 db: test user: root [ normal query ] SET NAMES utf8
2019-09-19 17:13:49 127.0.0.1:36436-127.0.0.1:3306 db: test user: root [ normal query ] set autocommit=0
2019-09-19 17:13:49 127.0.0.1:36436-127.0.0.1:3306 db: test user: root [ normal query ] SELECT VERSION()
2019-09-19 17:13:49 127.0.0.1:36436-127.0.0.1:3306 db: test user: root [ normal query ] DROP TABLE IF EXISTS jige003
2019-09-19 17:13:49 127.0.0.1:36436-127.0.0.1:3306 db: test user: root [ normal query ] CREATE TABLE jige003 (          name  CHAR(20) NOT NULL,          mail  CHAR(20),          age INT           )
2019-09-19 17:13:49 127.0.0.1:36436-127.0.0.1:3306 db: test user: root [ normal query ] INSERT INTO jige003(name,          mail, age)          VALUES ('jige003', 'jige003@mial.com', 100)
2019-09-19 17:13:49 127.0.0.1:36436-127.0.0.1:3306 db: test user: root [ normal query ] commit
2019-09-19 17:13:49 127.0.0.1:36436-127.0.0.1:3306 db: test user: root [ normal query ] select * from jige003 where name = 'jige003'  and age = 100
```

### 参考文档
 * https://dev.mysql.com/doc/internals/en/client-server-protocol.html
 * https://github.com/mysql/mysql-server/blob/5.5/include/mysql_com.h
