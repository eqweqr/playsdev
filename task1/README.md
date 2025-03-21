# Task1

## Задание 1

Определить ip сайта [google.com](http://google.com/) и проверить его доступность;

```bash
$ nslookup google.com

```

```bash
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
Name:	google.com
Address: 64.233.161.138
Name:	google.com
Address: 64.233.161.102
Name:	google.com
Address: 64.233.161.100
Name:	google.com
Address: 64.233.161.101
Name:	google.com
Address: 64.233.161.113
Name:	google.com
Address: 64.233.161.139
Name:	google.com
Address: 2a00:1450:4010:c02::8a
Name:	google.com
Address: 2a00:1450:4010:c02::71
Name:	google.com
Address: 2a00:1450:4010:c02::65
Name:	google.com
Address: 2a00:1450:4010:c02::66

```

```bash
$ ping -c 1 64.233.161.138

```

```bash
PING 64.233.161.138 (64.233.161.138) 56(84) bytes of data.
64 bytes from 64.233.161.138: icmp_seq=1 ttl=59 time=17.8 ms

--- 64.233.161.138 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 17.760/17.760/17.760/0.000 ms

```

## Задание 2

Определить маршрут следования пакета от инстанса до [google.com](http://google.com/);

```bash
traceroute google.com

```

```bash
traceroute to google.com (64.233.161.138), 30 hops max, 60 byte packets
 1  _gateway (192.168.0.1)  3.396 ms  3.348 ms  3.278 ms
 2  * * *
 3  192.168.126.222 (192.168.126.222)  3.183 ms  3.164 ms  3.141 ms
 4  77.37.250.47 (77.37.250.47)  6.375 ms  3.101 ms  6.335 ms
 5  72.14.209.81 (72.14.209.81)  6.315 ms  6.295 ms *
 6  lh-in-f138.1e100.net (64.233.161.138)  50.004 ms  36.268 ms  36.278 ms

```

## Задание 3

Определить какие порты инстанса используются в данный момент сервисами и определить какое приложение работает на порту 80;

```bash
$ netstat -ltupan | awk '{printf $4 "\\n"}' | sed -E "s/^[a-z,A-Z,(].*$|.*://g" | sort -u

```

```bash
22
29517
41216
443
47158
50881
52440
53
64912
80
9090
9091
9092

```

```bash
$ netstat -ltupan | grep :80

```

```bash
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      571/nginx: master p
tcp6       0      0 :::80                   :::*                    LISTEN      571/nginx: master p

```

## Задание 4

Показать какие ip routes настроены на машине, показать какой ip у твоей машины, какой hostname
```bash
$ ip route
```
```console
default via 10.0.85.2 dev outline-tun0 metric 10 
10.0.85.2 dev outline-tun0 scope link src 10.0.85.1 
104.164.54.150 via 192.168.0.1 dev wlo1 metric 5 
169.254.0.0/16 dev outline-tun0 scope link metric 1000 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown 
192.168.0.0/24 dev wlo1 proto kernel scope link src 192.168.0.11 metric 600 
192.168.49.0/24 dev br-ad6034fd3fc6 proto kernel scope link src 192.168.49.1 linkdown
```
```bash
$ hostname -I
```
```console
192.168.0.11 10.0.85.1 172.17.0.1 192.168.49.1
```
```bash
$ hostname
```
```console
leo-HP-Laptop-15s-eq2xxx
```

## Задание 5

Показать таблицу iptables, запретить входящие ICMP пакеты и показать что ping отвалился;
```bash
sudo iptables -L
```
```console
Chain INPUT (policy DROP)
target     prot opt source               destination         
ufw-before-logging-input  all  --  anywhere             anywhere            
ufw-before-input  all  --  anywhere             anywhere            
ufw-after-input  all  --  anywhere             anywhere            
ufw-after-logging-input  all  --  anywhere             anywhere            
ufw-reject-input  all  --  anywhere             anywhere            
ufw-track-input  all  --  anywhere             anywhere            

Chain FORWARD (policy DROP)
target     prot opt source               destination         
DOCKER-USER  all  --  anywhere             anywhere            
DOCKER-ISOLATION-STAGE-1  all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
DOCKER     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
DOCKER     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ufw-before-logging-forward  all  --  anywhere             anywhere            
ufw-before-forward  all  --  anywhere             anywhere            
ufw-after-forward  all  --  anywhere             anywhere            
ufw-after-logging-forward  all  --  anywhere             anywhere            
ufw-reject-forward  all  --  anywhere             anywhere            
ufw-track-forward  all  --  anywhere             anywhere            

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
ufw-before-logging-output  all  --  anywhere             anywhere            
ufw-before-output  all  --  anywhere             anywhere            
ufw-after-output  all  --  anywhere             anywhere            
ufw-after-logging-output  all  --  anywhere             anywhere            
ufw-reject-output  all  --  anywhere             anywhere            
ufw-track-output  all  --  anywhere             anywhere            

Chain DOCKER (2 references)
target     prot opt source               destination         

Chain DOCKER-ISOLATION-STAGE-1 (1 references)
target     prot opt source               destination         
DOCKER-ISOLATION-STAGE-2  all  --  anywhere             anywhere            
DOCKER-ISOLATION-STAGE-2  all  --  anywhere             anywhere            
RETURN     all  --  anywhere             anywhere            

Chain DOCKER-ISOLATION-STAGE-2 (2 references)
target     prot opt source               destination         
DROP       all  --  anywhere             anywhere            
DROP       all  --  anywhere             anywhere            
RETURN     all  --  anywhere             anywhere            

Chain DOCKER-USER (1 references)
target     prot opt source               destination         
RETURN     all  --  anywhere             anywhere            

Chain ufw-after-forward (1 references)
target     prot opt source               destination         

Chain ufw-after-input (1 references)
target     prot opt source               destination         
ufw-skip-to-policy-input  udp  --  anywhere             anywhere             udp dpt:netbios-ns
ufw-skip-to-policy-input  udp  --  anywhere             anywhere             udp dpt:netbios-dgm
ufw-skip-to-policy-input  tcp  --  anywhere             anywhere             tcp dpt:netbios-ssn
ufw-skip-to-policy-input  tcp  --  anywhere             anywhere             tcp dpt:microsoft-ds
ufw-skip-to-policy-input  udp  --  anywhere             anywhere             udp dpt:bootps
ufw-skip-to-policy-input  udp  --  anywhere             anywhere             udp dpt:bootpc
ufw-skip-to-policy-input  all  --  anywhere             anywhere             ADDRTYPE match dst-type BROADCAST

Chain ufw-after-logging-forward (1 references)
target     prot opt source               destination         
LOG        all  --  anywhere             anywhere             limit: avg 3/min burst 10 LOG level warning prefix "[UFW BLOCK] "

Chain ufw-after-logging-input (1 references)
target     prot opt source               destination         
LOG        all  --  anywhere             anywhere             limit: avg 3/min burst 10 LOG level warning prefix "[UFW BLOCK] "

Chain ufw-after-logging-output (1 references)
target     prot opt source               destination         

Chain ufw-after-output (1 references)
target     prot opt source               destination         

Chain ufw-before-forward (1 references)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
ACCEPT     icmp --  anywhere             anywhere             icmp destination-unreachable
ACCEPT     icmp --  anywhere             anywhere             icmp time-exceeded
ACCEPT     icmp --  anywhere             anywhere             icmp parameter-problem
ACCEPT     icmp --  anywhere             anywhere             icmp echo-request
ufw-user-forward  all  --  anywhere             anywhere            

Chain ufw-before-input (1 references)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
ufw-logging-deny  all  --  anywhere             anywhere             ctstate INVALID
DROP       all  --  anywhere             anywhere             ctstate INVALID
ACCEPT     icmp --  anywhere             anywhere             icmp destination-unreachable
ACCEPT     icmp --  anywhere             anywhere             icmp time-exceeded
ACCEPT     icmp --  anywhere             anywhere             icmp parameter-problem
ACCEPT     icmp --  anywhere             anywhere             icmp echo-request
ACCEPT     udp  --  anywhere             anywhere             udp spt:bootps dpt:bootpc
ufw-not-local  all  --  anywhere             anywhere            
ACCEPT     udp  --  anywhere             224.0.0.251          udp dpt:mdns
ACCEPT     udp  --  anywhere             239.255.255.250      udp dpt:1900
ufw-user-input  all  --  anywhere             anywhere            

Chain ufw-before-logging-forward (1 references)
target     prot opt source               destination         

Chain ufw-before-logging-input (1 references)
target     prot opt source               destination         

Chain ufw-before-logging-output (1 references)
target     prot opt source               destination         

Chain ufw-before-output (1 references)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
ufw-user-output  all  --  anywhere             anywhere            

Chain ufw-logging-allow (0 references)
target     prot opt source               destination         
LOG        all  --  anywhere             anywhere             limit: avg 3/min burst 10 LOG level warning prefix "[UFW ALLOW] "

Chain ufw-logging-deny (2 references)
target     prot opt source               destination         
RETURN     all  --  anywhere             anywhere             ctstate INVALID limit: avg 3/min burst 10
LOG        all  --  anywhere             anywhere             limit: avg 3/min burst 10 LOG level warning prefix "[UFW BLOCK] "

Chain ufw-not-local (1 references)
target     prot opt source               destination         
RETURN     all  --  anywhere             anywhere             ADDRTYPE match dst-type LOCAL
RETURN     all  --  anywhere             anywhere             ADDRTYPE match dst-type MULTICAST
RETURN     all  --  anywhere             anywhere             ADDRTYPE match dst-type BROADCAST
ufw-logging-deny  all  --  anywhere             anywhere             limit: avg 3/min burst 10
DROP       all  --  anywhere             anywhere            

Chain ufw-reject-forward (1 references)
target     prot opt source               destination         

Chain ufw-reject-input (1 references)
target     prot opt source               destination         

Chain ufw-reject-output (1 references)
target     prot opt source               destination         

Chain ufw-skip-to-policy-forward (0 references)
target     prot opt source               destination         
DROP       all  --  anywhere             anywhere            

Chain ufw-skip-to-policy-input (7 references)
target     prot opt source               destination         
DROP       all  --  anywhere             anywhere            

Chain ufw-skip-to-policy-output (0 references)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere            

Chain ufw-track-forward (1 references)
target     prot opt source               destination         

Chain ufw-track-input (1 references)
target     prot opt source               destination         

Chain ufw-track-output (1 references)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             ctstate NEW
ACCEPT     udp  --  anywhere             anywhere             ctstate NEW

Chain ufw-user-forward (1 references)
target     prot opt source               destination         

Chain ufw-user-input (1 references)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:1022

Chain ufw-user-limit (0 references)
target     prot opt source               destination         
LOG        all  --  anywhere             anywhere             limit: avg 3/min burst 5 LOG level warning prefix "[UFW LIMIT BLOCK] "
REJECT     all  --  anywhere             anywhere             reject-with icmp-port-unreachable

Chain ufw-user-limit-accept (0 references)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere            

Chain ufw-user-logging-forward (0 references)
target     prot opt source               destination         

Chain ufw-user-logging-input (0 references)
target     prot opt source               destination         

Chain ufw-user-logging-output (0 references)
target     prot opt source               destination         

Chain ufw-user-output (1 references)
target     prot opt source               destination
```
## Задание 6

На локалке сделать так, чтобы dns запись [google.com](http://google.com/) вела на другой сайт;
Добавляем в /etc/hosts запись:
```console
104.164.54.150  google.com
```
Проверяем с помощью curl:
```bash
$ curl google.com
```
```console 
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```
## Задание 7
Просмотреть список запущеных процессов, объяснить вывод команды ps auxft, объяснить какой процесс под PID 1, показать дочерние процессы процесса PID 1. Что такое RSS, VSZ, NI, PRI, STAT, какой процесс используется твоим терминалом;
```bash
ps ax
```
```console
PID TTY      STAT   TIME COMMAND
      1 ?        Ss     0:08 /sbin/init
      2 ?        S      0:00 [kthreadd]
      3 ?        I<     0:00 [rcu_gp]
      4 ?        I<     0:00 [rcu_par_gp]
      5 ?        I<     0:00 [slub_flushwq]
      6 ?        I<     0:00 [netns]
      8 ?        I<     0:00 [kworker/0:0H-events_highpri]
     10 ?        I<     0:00 [mm_percpu_wq]
....
```
### ps auxft
u - user oriented format(добавляет user, %CPU, %MEM, VSZ, RSS, STAT, START, COMMAND)
a - для всех пользователей
x - процессы не связанные с терминалами
f - в виде дерева выводит процессы(те связь между родительскими и дочерними процессами)
t - позволяет фильтровать по терминалам к которым привязан процесс
PID - первый процесс, запускаемый ядром при загрузке система. Родитель для всех остальных. init системы и запуск осатльных процессов
```bash
$ ps --ppid=1 eo user,pid,ppid,commps --ppid=1 eo 
```

```console
root         332       1 systemd-journal
root         373       1 multipathd
root         374       1 systemd-udevd
systemd+     418       1 systemd-timesyn
systemd+     495       1 systemd-network
systemd+     502       1 systemd-resolve
message+     516       1 dbus-daemon
root         521       1 networkd-dispat
root         524       1 snapd
root         525       1 systemd-logind
root         527       1 containerd
root         536       1 qemu-ga
root         537       1 unattended-upgr
root         571       1 nginx
root         599       1 agetty
root         607       1 sshd
root         668       1 dockerd
root         946       1 containerd-shim
root         951       1 containerd-shim
root       21571       1 packagekitd
root       21575       1 polkitd
root      225303       1 systemd
```

```bash
$ ps
```
```console
PID TTY          TIME CMD
 230253 pts/1    00:00:00 bash
 231406 pts/1    00:00:00 ps
```
- VMZ (indication of the maximum amount of memory a process can use if it loads all of its functions and libraries into physical memory) 
- RSS is Resident Set Size. This is the size of memory that a process has currently used to load all of its pages. Несколько раз учитывает динамические библиотеки.
- Ni (nice value)
- PRI (приоритет процесса. PR = 20+NI). При использует планировщик
- STAT - состояние процесса
```console
D    uninterruptible sleep (usually IO)
               I    Idle kernel thread
               R    running or runnable (on run queue)
               S    interruptible sleep (waiting for an event to complete)
               T    stopped by job control signal
               t    stopped by debugger during the tracing
               W    paging (not valid since the 2.6.xx kernel)
               X    dead (should never be seen)
               Z    defunct ("zombie") process, terminated but not reaped by its parent

       For BSD formats and when the stat keyword is used, additional characters may be displayed:

               <    high-priority (not nice to other users)
               N    low-priority (nice to other users)
               L    has pages locked into memory (for real-time and custom IO)
               s    is a session leader
               l    is multi-threaded (using CLONE_THREAD, like NPTL pthreads do)
               +    is in the foreground process group

```

## Задание 8

Показать какие службы systemd сейчас запущены и найти службу nginx, сделать hard и easy рестарт сервиса nginx, объяснить различие;
```bash
systemctl
```
![](https://github.com/eqweqr/playsdev/blob/master/imgs/Screenshot%20from%202025-03-21%2013-45-07.png)

```bash
$ systemctl reload nginx
$ nginx -s reload
```
Обновляет конфигурацию, не останавливает сервис
```bash
$ systemctl restart nginx
```
## Задание 9

Определить процессы которые имеют открытые файлы в директории /var/log, объяснить вывод использованной команды;
``` bash
$ sudo lsof +D /var/log
```
```console
COMMAND      PID     USER   FD   TYPE DEVICE SIZE/OFF   NODE NAME
systemd-j    332     root  mem    REG    8,2 25165824    791 /var/log/journal/9f4e69b5ff494edba57fec6aeaec5e0e/system.journal
systemd-j    332     root  mem    REG    8,2 75497472    686 /var/log/journal/9f4e69b5ff494edba57fec6aeaec5e0e/system@7cc9a05f01cd4ab8822c133cb6942f34-0000000000000001-0006308cfb864585.journal
systemd-j    332     root   20u   REG    8,2 75497472    686 /var/log/journal/9f4e69b5ff494edba57fec6aeaec5e0e/system@7cc9a05f01cd4ab8822c133cb6942f34-0000000000000001-0006308cfb864585.journal
systemd-j    332     root   28u   REG    8,2 25165824    791 /var/log/journal/9f4e69b5ff494edba57fec6aeaec5e0e/system.journal
unattende    537     root    3w   REG    8,2      339   8336 /var/log/unattended-upgrades/unattended-upgrades-shutdown.log
nginx     232244     root    2w   REG    8,2    44004 153729 /var/log/nginx/error.log
nginx     232244     root    4w   REG    8,2  5510990 153727 /var/log/nginx/access.log
nginx     232244     root    5w   REG    8,2    44004 153729 /var/log/nginx/error.log
nginx     232245 www-data    2w   REG    8,2    44004 153729 /var/log/nginx/error.log
nginx     232245 www-data    4w   REG    8,2  5510990 153727 /var/log/nginx/access.log
nginx     232245 www-data    5w   REG    8,2    44004 153729 /var/log/nginx/error.log
```

## Задание 10

Показать сколько места занято на дисках, показать сколько места на диске занимает директория /var/log/. Аналогично показать сколько занято inodes на дисках и в директории /var/log/;
```bash
$ df
```
```console
Filesystem       Inodes   IUsed    IFree IUse% Mounted on
tmpfs            931265    1449   929816    1% /run
/dev/nvme0n1p5  9158656 1252397  7906259   14% /
tmpfs            931265     168   931097    1% /dev/shm
tmpfs            931265       4   931261    1% /run/lock
efivarfs              0       0        0     - /sys/firmware/efi/efivars
/dev/nvme0n1p6 15097856 1231360 13866496    9% /prevhome
/dev/nvme0n1p1        0       0        0     - /boot/efi
tmpfs            186253     206   186047    1% /run/user/1000
```
```bash
$ df -i
```
```console
Filesystem       Inodes   IUsed    IFree IUse% Mounted on
tmpfs            931265    1449   929816    1% /run
/dev/nvme0n1p5  9158656 1252397  7906259   14% /
tmpfs            931265     168   931097    1% /dev/shm
tmpfs            931265       4   931261    1% /run/lock
efivarfs              0       0        0     - /sys/firmware/efi/efivars
/dev/nvme0n1p6 15097856 1231360 13866496    9% /prevhome
/dev/nvme0n1p1        0       0        0     - /boot/efi
tmpfs            186253     206   186047    1% /run/user/1000
```
```bash
du -s /var/log
```
```console
2,9G	/var/log
```

```bash
sudo du -s --inode /var/log
```
```console
sudo du -s --inode /var/log
```


## Задание 11

Показать с помощью man за что отвечает флаг -I в команде iptables (научиться ориентироваться в мануале).
![](https://github.com/eqweqr/playsdev/blob/master/imgs/Screenshot%20from%202025-03-21%2012-26-16.png)