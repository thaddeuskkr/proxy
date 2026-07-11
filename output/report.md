# Proxy Rule Report

## output/direct.list

- Sources: 6
- Fetched active lines: 3779
- Raw emitted lines: 3779
- Final emitted lines: 3772
- Removed exact duplicates: 1
- Removed covered CIDRs: 6
- Removed domain redundancies: 0

### Rule Types After

- DOMAIN: 14
- DOMAIN-KEYWORD: 8
- DOMAIN-SUFFIX: 3699
- GEOIP: 1
- IP-CIDR: 19
- USER-AGENT: 31

### Conversions

- domain_bare_to_suffix: 17
- domain_leading_dot_to_suffix: 3672
- dot_keyword_to_suffix: 1

### Largest Sources

- 3689: rule/Shadowrocket/China/China_Domain.list
- 63: rule/Shadowrocket/China/China.list
- 17: rule/Shadowrocket/SteamCN/SteamCN.list
- 7: defaults/direct.list
- 2: rule/Shadowrocket/AppStore/AppStore.list

### Warning Examples

- Complex keyword preserved: DOMAIN-KEYWORD,alicdn
- Complex keyword preserved: DOMAIN-KEYWORD,alipay
- Complex keyword preserved: DOMAIN-KEYWORD,aliyun
- Complex keyword preserved: DOMAIN-KEYWORD,baidu
- Complex keyword preserved: DOMAIN-KEYWORD,beplay
- Complex keyword preserved: DOMAIN-KEYWORD,microsoft
- Complex keyword preserved: DOMAIN-KEYWORD,officecdn
- Complex keyword preserved: DOMAIN-KEYWORD,taobao

## output/proxy.list

- Sources: 15
- Fetched active lines: 5408
- Raw emitted lines: 5408
- Final emitted lines: 5392
- Removed exact duplicates: 16
- Removed covered CIDRs: 0
- Removed domain redundancies: 0

### Rule Types After

- DOMAIN: 11
- DOMAIN-KEYWORD: 47
- DOMAIN-SUFFIX: 4242
- IP-ASN: 7
- IP-CIDR: 991
- URL-REGEX: 1
- USER-AGENT: 93

### Conversions

- domain_bare_to_suffix: 46
- domain_leading_dot_to_suffix: 2825

### Largest Sources

- 1560: rule/Shadowrocket/Apple/Apple_Domain.list
- 1311: rule/Shadowrocket/GlobalMedia/GlobalMedia_Domain.list
- 1021: rule/Shadowrocket/GlobalMedia/GlobalMedia.list
- 698: rule/Shadowrocket/Google/Google.list
- 570: rule/Shadowrocket/Facebook/Facebook.list

### Warning Examples

- Complex keyword preserved: DOMAIN-KEYWORD,naiun
- Complex keyword preserved: DOMAIN-KEYWORD,nicegram
- Complex keyword preserved: DOMAIN-KEYWORD,appspot
- Complex keyword preserved: DOMAIN-KEYWORD,blogspot
- Complex keyword preserved: DOMAIN-KEYWORD,gmail
- Complex keyword preserved: DOMAIN-KEYWORD,google
- Complex keyword preserved: DOMAIN-KEYWORD,recaptcha
- Complex keyword preserved: DOMAIN-KEYWORD,openai
- Complex keyword preserved: DOMAIN-KEYWORD,instagram
- Complex keyword preserved: DOMAIN-KEYWORD,facebook
