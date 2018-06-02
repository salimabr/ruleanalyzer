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

Focusing on Destination addresses, free Emerging Threat Rules (as of 6/1/2018) reports the following destinations being addressed by the most rules.

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

If we drill down to Destination Ports we get the following:

<pre><code>
$ python ruleanalyzer.py "rules/emerging-all.rules" --report destination_port | sort | uniq -c | sort -r | head -25
9629 any
4280 $HTTP_PORTS
1414 53
 248 445
 248 139
 172 $ORACLE_PORTS
  87 25
  60 443
  59 111
  56 1024:
  51 21
  45 1024:65535
  43 587
  35 23
  30 2323
  28 5060
  19 161
  19 143
  17 1433
  17 135
  16 6893
  16 6892
  16 3306
  14 8080
  14 80
</code></pre>

Finally, if you are specifically interested in the rules associated with port 6892 as indicated above, you can run the following command which will print out the associated rule:

<pre><code>
$ python ruleanalyzer.py "rules/emerging-all.rules" --report destination_port --criteria 6892 
6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (1)"; dsize:13<>32; content:"0"; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023612; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (2)"; dsize:13<>32; content:"1"; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023613; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (3)"; dsize:13<>32; content:"2"; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023614; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (4)"; dsize:13<>32; content:"3"; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023615; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (5)"; dsize:13<>32; content:"4"; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023616; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (6)"; dsize:13<>32; content:"5"; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023617; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (7)"; dsize:13<>32; content:"6"; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023618; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (8)"; dsize:13<>32; content:"7"; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023619; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (9)"; dsize:13<>32; content:"8"; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023620; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (10)"; dsize:13<>32; content:"9"; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023621; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (11)"; dsize:13<>32; content:"a"; nocase; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023622; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (12)"; dsize:13<>32; content:"b"; nocase; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023623; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (13)"; dsize:13<>32; content:"c"; nocase; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023624; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (14)"; dsize:13<>32; content:"d"; nocase; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023625; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (15)"; dsize:13<>32; content:"e"; nocase; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023626; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)

6892: alert udp $HOME_NET any -> $EXTERNAL_NET [6892,6893] (msg:"ET TROJAN Ransomware/Cerber Checkin M3 (16)"; dsize:13<>32; content:"f"; nocase; depth:1; pcre:"/^[a-f0-9]{13,30}$/Ri"; threshold: type both, track by_src, count 1, seconds 60; metadata: former_category TROJAN; reference:md5,42c677d6d8f42acd8736c4b8c75ce505; reference:md5,7f6290c02465625828cfce6a8014c34a; reference:md5,d8b2d2a5f6da2872e147011d2ea85d71; classtype:trojan-activity; sid:2023627; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Cerber, signature_severity Major, created_at 2016_12_12, malware_family Ransomware_Cerber, updated_at 2017_04_14;)
</code></pre>

If you wanted to know the most popular "content" options in all of your rules, run this:

<pre><code>
$ python ruleanalyzer.py "rules/emerging-all.rules" --report option | egrep "content:" | sort | uniq -c | sort -r | head -25
1535 content:"GET"
 969 content:"POST"
 706 content:"SELECT"
 646 content:"|01 00 00 01 00 00 00 00 00 00|"
 640 content:!"Referer|3a|"
 480 content:"|00|"
 462 uricontent:"SELECT"
 438 content:"UNION"
 374 content:"DELETE"
 369 content:"INSERT"
 367 content:"UPDATE"
 351 content:"id="
 289 content:"GET "
 287 uricontent:"UNION"
 265 content:"|05|"
 251 content:"&|00|"
 248 content:!"Accept"
 212 uricontent:"INSERT"
 211 uricontent:"DELETE"
 210 uricontent:"UPDATE"
 199 content:"/index.php?"
 189 uricontent:"id="
 183 content:"FROM"
 165 content:"../"
 146 content:"|FF|SMB"
</code></pre>
