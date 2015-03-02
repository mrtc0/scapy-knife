# scapy-knife
The knife of Scapy

## これはなに

Scapyを使ったツールキット.  

## Usage

### checkdns.py

pcapファイルからDNSによる問い合わせ先をVirusTotalでスキャンします.  
VirusTotal APIが必要です.  
  
```
./checkdns.py <pcap>
WARNING: No route found for IPv6 destination :: (no default route?)
[*] http://ourlittleponic.pw/
    Kaspersky       malware site
    Fortinet        malware site
[*] http://freepicscenter.pw/
[*] http://freecenterpics.pw/
[*] http://picsfreecenter.pw/
```
  

