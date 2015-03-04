# scapy-knife
The knife of Scapy

## これはなに

Scapyを使ったツールキット.  

## Usage

### checkdns.py

pcapファイルからDNSによる問い合わせ先をVirusTotalでスキャンします.  
VirusTotal APIが必要です.  
  
```
# ./checkdns.py <pcap>
WARNING: No route found for IPv6 destination :: (no default route?)
[*] http://ourlittleponic.pw/
    Kaspersky       malware site
    Fortinet        malware site
[*] http://freepicscenter.pw/
[*] http://freecenterpics.pw/
[*] http://picsfreecenter.pw/
```
  
### arpspoof.py

ARP Spoofingを行うスクリプトです.  
``` echo 1 > /proc/sys/net/ipv4/ip_forward ``` でフォワーディングの設定をしておいてください.  
第1引数に自身のMacアドレス, 第2引数にターゲットIPアドレス, 第3引数にルーターのIPアドレスを指定するなどしてください.  
  
```
# ./arpspoof.py <Attacker Physical Address> <Target IP> <Router IP>

```
  
### arpmonitor.py

ARPパケットの監視及び, ARP Spoofingの検知を行うスクリプトです.  
  

```
# ./arpmonitor.py                                                                                                            
WARNING: No route found for IPv6 destination :: (no default route?)
{'192.168.1.108': '08:00:27:45:d0:59', '192.168.1.102': '00:8c:fa:yy:yy:yy', '192.168.1.2': 'dc:fb:02:xx:xx:xx'}
Request: 192.168.1.101 -> 192.168.1.2  
Reply: dc:fb:02:xx:xx:xx -> 192.168.1.2 
Request: 192.168.1.101 -> 192.168.1.2  
Reply: dc:fb:02:xx:xx:xx -> 192.168.1.2 
[*] Detect Spoofing!!
[*] 192.168.1.2 : dc:fb:02:xx:xx:xx to 08:00:27:45:d0:59
Reply: 08:00:27:45:d0:59 -> 192.168.1.2 
Request: 192.168.1.2 -> 192.168.1.108  
[*] Detect Spoofing!!
[*] 192.168.1.2 : dc:fb:02:xx:xx:xx to 08:00:27:45:d0:59
Reply: 08:00:27:45:d0:59 -> 192.168.1.2 
[*] Detect Spoofing!!
[*] 192.168.1.2 : dc:fb:02:xx:xx:xx to 08:00:27:45:d0:59
Reply: 08:00:27:45:d0:59 -> 192.168.1.2 
Reply: dc:fb:02:xx:xx:xx -> 192.168.1.2 
```
  
  
### portscan/scan.py

ポートスキャナーです.  
TCP SYN, ACK, FIN, Xmas, Nullスキャンができます(2015-03-03)  
コンマ区切りでポートを指定してください. 指定がない場合はCommon Portsをスキャンします.  

```
# ./scan.py -t 192.168.1.109 -S 
WARNING: No route found for IPv6 destination :: (no default route?)
[*]Result for 192.168.1.109 
    Port         State
    22           Open
    80           Open
Scanned 82 ports, Closed 80 ports. 192.168.1.109
  
# scan.py -t 192.168.1.109 -p 22,80,443,12345,25252 -A
WARNING: No route found for IPv6 destination :: (no default route?)
[*]Result for 192.168.1.109 
    Port         State
    22           Unfiltered
    80           Unfiltered
    443          Unfiltered
    12345        Filtered (Statefull)
    25252        Filtered (Statefull)
Scanned 5 ports, Closed 0 ports. 192.168.1.109
```
  
### ReturnSA.py

パケット全てにSYN, ACKを返します.  
なのでSYNスキャンではすべてのポートが開いているように見えます.  
OSがRST, ACKを返さないようにiptablesを設定しておく必要があります.  
  
```
# iptables -A OUTPUT -p tcp --tcp-flags ALL RST,ACK -d 192.168.1.101 -j DROP
# netstat -antp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
# ./returnSA.py
```
  
```
# nmap -sS 192.168.11.14                                                                                                                  

Starting Nmap 6.47 ( http://nmap.org ) at 2015-03-04 20:22 JST
Nmap scan report for 192.168.1.101
Host is up (4.2s latency).
PORT      STATE SERVICE
1/tcp     open  tcpmux
3/tcp     open  compressnet
4/tcp     open  unknown
6/tcp     open  unknown
7/tcp     open  echo
9/tcp     open  discard
13/tcp    open  daytime
17/tcp    open  qotd
19/tcp    open  chargen
20/tcp    open  ftp-data
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
24/tcp    open  priv-mail
25/tcp    open  smtp
26/tcp    open  rsftp
30/tcp    open  unknown
32/tcp    open  unknown
33/tcp    open  dsp
~ snip ~
```


