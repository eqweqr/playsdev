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

## Задание 5

Показать таблицу iptables, запретить входящие ICMP пакеты и показать что ping отвалился;

## Задание 6

На локалке сделать так, чтобы dns запись [google.com](http://google.com/) вела на другой сайт;

## Задание 7

Просмотреть список запущеных процессов, объяснить вывод команды ps auxft, объяснить какой процесс под PID 1, показать дочерние процессы процесса PID 1. Что такое RSS, VSZ, NI, PRI, STAT, какой процесс используется твоим терминалом;

## Задание 8

Показать какие службы systemd сейчас запущены и найти службу nginx, сделать hard и easy рестарт сервиса nginx, объяснить различие;

## Задание 9

Определить процессы которые имеют открытые файлы в директории /var/log, объяснить вывод использованной команды;

## Задание 10

Показать сколько места занято на дисках, показать сколько места на диске занимает директория /var/log/. Аналогично показать сколько занято inodes на дисках и в директории /var/log/;

## Задание 11

Показать с помощью man за что отвечает флаг -I в команде iptables (научиться ориентироваться в мануале).
![](https://github.com/eqweqr/playsdev/blob/master/imgs/Screenshot%20from%202025-03-21%2012-26-16.png)