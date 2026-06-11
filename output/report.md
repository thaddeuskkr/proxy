# Proxy Rule Report

## output/direct.list

- Sources: 7
- Fetched active lines: 27014
- Raw emitted lines: 27014
- Final emitted lines: 15427
- Removed exact duplicates: 103
- Removed covered CIDRs: 11484
- Removed domain redundancies: 0

### Rule Types After

- DOMAIN: 79
- DOMAIN-KEYWORD: 10
- DOMAIN-SUFFIX: 3861
- GEOIP: 1
- IP-CIDR: 11414
- USER-AGENT: 62

### Conversions

- domain_bare_to_suffix: 17
- domain_leading_dot_to_suffix: 3674
- dot_keyword_to_suffix: 1

### Largest Sources

- 22796: rule/Shadowrocket/ChinaIPs/ChinaIPs.list
- 3691: rule/Shadowrocket/China/China_Domain.list
- 440: rule/Shadowrocket/ChinaMedia/ChinaMedia.list
- 63: rule/Shadowrocket/China/China.list
- 17: rule/Shadowrocket/SteamCN/SteamCN.list

### Warning Examples

- Complex keyword preserved: DOMAIN-KEYWORD,alicdn
- Complex keyword preserved: DOMAIN-KEYWORD,alipay
- Complex keyword preserved: DOMAIN-KEYWORD,aliyun
- Complex keyword preserved: DOMAIN-KEYWORD,baidu
- Complex keyword preserved: DOMAIN-KEYWORD,beplay
- Complex keyword preserved: DOMAIN-KEYWORD,microsoft
- Complex keyword preserved: DOMAIN-KEYWORD,officecdn
- Complex keyword preserved: DOMAIN-KEYWORD,taobao
- Complex keyword preserved: DOMAIN-KEYWORD,bilibili
- Complex keyword preserved: DOMAIN-KEYWORD,qiyi

## output/proxy.list

- Sources: 21
- Fetched active lines: 6386
- Raw emitted lines: 6386
- Final emitted lines: 6338
- Removed exact duplicates: 46
- Removed covered CIDRs: 2
- Removed domain redundancies: 0

### Rule Types After

- DOMAIN: 21
- DOMAIN-KEYWORD: 50
- DOMAIN-SUFFIX: 5138
- IP-ASN: 7
- IP-CIDR: 1025
- URL-REGEX: 1
- USER-AGENT: 96

### Conversions

- domain_bare_to_suffix: 46
- domain_leading_dot_to_suffix: 2825

### Largest Sources

- 1560: rule/Shadowrocket/Apple/Apple_Domain.list
- 1311: rule/Shadowrocket/GlobalMedia/GlobalMedia_Domain.list
- 1021: rule/Shadowrocket/GlobalMedia/GlobalMedia.list
- 698: rule/Shadowrocket/Google/Google.list
- 671: rule/Shadowrocket/Microsoft/Microsoft.list

### Warning Examples

- Complex keyword preserved: DOMAIN-KEYWORD,nicegram
- Complex keyword preserved: DOMAIN-KEYWORD,appspot
- Complex keyword preserved: DOMAIN-KEYWORD,blogspot
- Complex keyword preserved: DOMAIN-KEYWORD,gmail
- Complex keyword preserved: DOMAIN-KEYWORD,google
- Complex keyword preserved: DOMAIN-KEYWORD,recaptcha
- Complex keyword preserved: DOMAIN-KEYWORD,openai
- Complex keyword preserved: DOMAIN-KEYWORD,instagram
- Complex keyword preserved: DOMAIN-KEYWORD,facebook
- Complex keyword preserved: DOMAIN-KEYWORD,fbcdn
