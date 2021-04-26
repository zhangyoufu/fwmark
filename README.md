# What's this?

This Python3 script create a new cgroup and attach eBPF program to enforce fwmark (SO_MARK) as soon as the socket is created. Inspired by `ip vrf exec`.

This should be useful for diagnosing multi-homing network. (in case you configured policy routing correctly)

```
root@localhost:~# ./fwmark.py 1 curl ip.fm
IP: 58.32.X.X 来自: 中国 上海 电信

root@localhost:~# ./fwmark.py 2 curl ip.fm
IP: 112.64.X.X 来自: 中国 上海 联通

root@localhost:~# ./fwmark.py 1234
(fwmark 1234) root@localhost:~# python3
Python 3.8.6 (default, Sep 25 2020, 09:36:53)
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket
>>> socket.socket().getsockopt(socket.SOL_SOCKET, socket.SO_MARK)
1234
>>> exit()
(fwmark 1234) root@localhost:~# exit
exit
root@localhost:~# 
```

# Usage

```
% ./fwmark.py --help
usage: fwmark.py [-h] [--cgroup2 CGROUP2] fwmark ...

run program in a new cgroup with specified fwmark

positional arguments:
  fwmark             fwmark to be applied
  command            command to be executed (default to $SHELL -l if omitted)

optional arguments:
  -h, --help         show this help message and exit
  --cgroup2 CGROUP2  cgroup2 mountpoint, usually under /sys/fs/cgroup
```

# Shell Prompt

For bash: `echo 'PS1="\${FWMARK:+(fwmark \$FWMARK) }$PS1"' >>~/.bashrc`
