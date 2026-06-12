# Proxy Rule Report

## output/direct.list

- Sources: 5
- Fetched active lines: 3778
- Raw emitted lines: 3778
- Final emitted lines: 3771
- Removed exact duplicates: 1
- Removed covered CIDRs: 6
- Removed domain redundancies: 0

### Rule Types After

- DOMAIN: 12
- DOMAIN-KEYWORD: 8
- DOMAIN-SUFFIX: 3700
- GEOIP: 1
- IP-CIDR: 19
- USER-AGENT: 31

### Conversions

- domain_bare_to_suffix: 17
- domain_leading_dot_to_suffix: 3674
- dot_keyword_to_suffix: 1

### Largest Sources

- 3691: rule/Shadowrocket/China/China_Domain.list
- 63: rule/Shadowrocket/China/China.list
- 17: rule/Shadowrocket/SteamCN/SteamCN.list
- 6: defaults/direct.list
- 1: defaults/direct.list:end

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
