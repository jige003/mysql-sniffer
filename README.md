# mysql-sniffer
> mysql sniffer network traffic 

### 功能
* 支持query 命令解析

### Usage
```
Copyright by jige003

Usage:
    mysql-sniffer [-h] -i interface -p port
```

### 日志
```
./mysql-sniffer -i lo
[*] sniffe on interface: lo
2019-09-06 18:23:02  127.0.0.1:41204 -> 127.0.0.1:3306 [ req ]  select * from user limit 1
2019-09-06 18:23:08  127.0.0.1:41204 -> 127.0.0.1:3306 [ req ]  show tables
```

### 参考文档
https://dev.mysql.com/doc/internals/en/client-server-protocol.html
https://github.com/mysql/mysql-server/blob/5.5/include/mysql_com.h
