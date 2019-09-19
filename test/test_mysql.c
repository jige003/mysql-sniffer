#include <stdio.h>
#include <mysql/mysql.h>
#include <string.h>

int main(void)
{
    MYSQL *conn = mysql_init(NULL);     //初始化服务器句柄
    /*登陆服务器*/
    if(!mysql_real_connect(conn, "127.0.0.1", "root", "ahg8eeY8", "test", 0, NULL, 0))  
    {
        fprintf(stderr, "mysql_real_connect: %s\n", mysql_error(conn));
        return -1;
    }

    MYSQL_STMT *stmt = mysql_stmt_init(conn); //创建MYSQL_STMT句柄

    char *query = "select * from jige003 where name = ? and age = ?";
    if(mysql_stmt_prepare(stmt, query, strlen(query)))
    {
        fprintf(stderr, "mysql_stmt_prepare: %s\n", mysql_error(conn));
        return -1;
    }

    int age = 100; 
    char name[20] = "jige003";

    MYSQL_BIND params[2];
    memset(params, 0, sizeof(params));
    params[0].buffer_type = MYSQL_TYPE_STRING;
    params[0].buffer = name;
    params[0].buffer_length = strlen(name);
    params[1].buffer_type = MYSQL_TYPE_LONG;
    params[1].buffer = &age;

    mysql_stmt_bind_param(stmt, params);
    mysql_stmt_execute(stmt);           //执行与语句句柄相关的预处理

    mysql_stmt_close(stmt);             
    mysql_close(conn);

    return 0;
}
