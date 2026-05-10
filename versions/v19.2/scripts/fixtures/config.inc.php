<?php
//全局session_start
session_start();
//全局居中设置时区
date_default_timezone_set('Asia/Shanghai');
//全局设置默认字符
header('Content-type:text/html;charset=utf-8');
//定义数据库连接参数
// 连接到DVWA容器的MySQL
define('DBHOST', '172.24.0.2'); // DVWA容器的新IP (wvs-net)
define('DBUSER', 'root'); // MySQL用户名
define('DBPW', ''); // 空密码
define('DBNAME', 'pikachu'); // 数据库名
define('DBPORT', '3306'); // MySQL端口

?>
