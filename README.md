# ruleanalyzer
Parses Snort/Suricata rules to generate reports to understand the signature coverage on your sensor with a given ruleset.  The goal is to assist the analyst with tuning their signatures for their specific environment.

<h2>Sample Reports:</h2>
This report indicates the free Emerging Threat Rules (as of 6/1/2018) heavily focuses on outbound HTTP traffic.  Depending on the position of the sensor in your network, you may identify additional signatures that could be disabled just based on this information.
<pre><code>
$ python ruleanalyzer.py "rules/emerging-all.rules" --report header | sort | uniq -c | sort -r | head -25
4010 alert http $HOME_NET any -> $EXTERNAL_NET any 
2184 alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS 
2147 alert http $EXTERNAL_NET any -> $HOME_NET any 
1840 alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS 
1199 alert udp $HOME_NET any -> any 53 
 968 alert http $EXTERNAL_NET any -> $HTTP_SERVERS any 
 467 alert tls $EXTERNAL_NET any -> $HOME_NET any 
 433 alert tcp $HOME_NET any -> $EXTERNAL_NET any 
 263 alert tls $EXTERNAL_NET 443 -> $HOME_NET any 
 171 alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS 
 169 alert tcp $EXTERNAL_NET any -> $HOME_NET 445 
 167 alert tcp $EXTERNAL_NET any -> $HOME_NET 139 
 156 alert tcp $EXTERNAL_NET any -> $HOME_NET any 
 111 alert udp $HOME_NET any -> $EXTERNAL_NET 53 
  97 alert http any any -> $HTTP_SERVERS any 
  94 alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any 
  92 alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any 
  88 alert dns $HOME_NET any -> any any 
  72 alert tcp $EXTERNAL_NET 443 -> $HOME_NET any 
  71 alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS 
  70 alert http $HTTP_SERVERS any -> $EXTERNAL_NET any 
  65 alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS 
  63 alert dns $HOME_NET any -> any 53 
  60 alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS 
  52 alert http any any -> $HOME_NET any
  </code></pre>
  
For comparison, here are the report results for the Talos community rules as of 6/1/2018:
  <pre><code>
  $ python ruleanalyzer.py "rules/community-rules/community.rules" --report header | sort | uniq -c | sort -r | head -25
 474 alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS 
  82 alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any 
  46 alert tcp $HOME_NET any -> $EXTERNAL_NET any 
  27 alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS 
  24 alert tcp $EXTERNAL_NET any -> $HOME_NET any 
  16 alert tcp $HOME_NET [21,25,443,465,636,992,993,995,2484] -> $EXTERNAL_NET any 
  13 alert tcp $EXTERNAL_NET $FILE_DATA_PORTS -> $HOME_NET any 
  10 alert tcp $HOME_NET any -> $EXTERNAL_NET 443 
   9 alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 
   7 alert tcp any any -> $HOME_NET 445 
   6 alert tcp $HOME_NET any -> $EXTERNAL_NET [25,587] 
   6 alert tcp $EXTERNAL_NET any -> $HOME_NET [21,25,443,465,636,992,993,995,2484] 
   5 alert udp $HOME_NET any -> $EXTERNAL_NET 53 
   4 alert tcp $HOME_NET any -> $EXTERNAL_NET [21,25,443,465,636,992,993,995,2484] 
   4 alert tcp $EXTERNAL_NET any -> $HOME_NET 4786 
   4 alert tcp $EXTERNAL_NET any -> $HOME_NET 445 
   4 alert tcp $EXTERNAL_NET any -> $HOME_NET 139 
   4 alert tcp $EXTERNAL_NET [443,447,449] -> $HOME_NET any 
   3 alert udp $HOME_NET any -> $EXTERNAL_NET any 
   3 alert tcp any any -> any $HTTP_PORTS 
   3 alert tcp $HOME_NET any -> $EXTERNAL_NET 80 
   3 alert tcp $HOME_NET 445 -> any any 
   3 alert tcp $EXTERNAL_NET 21 -> $HOME_NET any 
   3 alert tcp $EXTERNAL_NET 1025: -> $HOME_NET any 
   2 alert udp $EXTERNAL_NET any -> $HOME_NET [500,848,4500,4848]
   </code></pre>
  
  <pre><code>
  $ python ruleanalyzer.py "rules/emerging-all.rules" --report destination | sort | uniq -c | sort -r | head -25
5279 $EXTERNAL_NET
5108 $HTTP_SERVERS
4603 $HOME_NET
1596 any
 202 $SQL_SERVERS
  30 $SMTP_SERVERS
   3 $DNS_SERVERS
   2 !255.255.255.255
   1 85.93.0.0/24
   1 82.163.143.135
   1 82.163.142.137
   1 31.184.192.0/24
   1 31.184.192.0/19
   1 224.0.0.2
   1 209.139.208.0/23
   1 195.22.26.192/26
   1 194.165.16.0/24
   1 11.11.11.11
   1 1.1.1.0
   1 $TELNET_SERVERS
   1 $AIM_SERVERS
   1 !8.28.150.0/24
   1 !78.108.112.0/20
   1 !72.5.190.0/24
   1 !70.42.29.0/27
  </code></pre>
