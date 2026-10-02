# soc-hunting-queries

A small, growing collection of hunting and detection queries I use as starting points in SOC and DFIR work, each with the context needed to adapt it: what it finds, which data source it needs, expected false positives and the ATT&CK mapping.

> **Read this first.** These are **templates**, not production detections. Field names, table names and telemetry vary by tenant, sensor version and log pipeline. Test every query on a short time range in your own environment and tune it against your normal activity before alerting on it. Nothing here comes from, or contains data from, any employer. Hostnames, domains and IPs in examples are invented.

## Contents

| Area | Query set | Platform |
|---|---|---|
| ClickFix (fake CAPTCHA, Win+R paste) | [`crowdstrike-falcon/clickfix-hunting.md`](crowdstrike-falcon/clickfix-hunting.md) | CrowdStrike Falcon Advanced Event Search |
| Office spawning scripting hosts | [`splunk/office-child-process.md`](splunk/office-child-process.md) | Splunk (Sysmon) |
| Suspicious scheduled tasks | [`sentinel-kql/suspicious-scheduled-task.md`](sentinel-kql/suspicious-scheduled-task.md) | Microsoft Sentinel (KQL) |
| JA4 clustering of distributed web attacks | [`splunk/waf-ja4-hunting.md`](splunk/waf-ja4-hunting.md), [`sentinel-kql/waf-ja4-hunting.md`](sentinel-kql/waf-ja4-hunting.md) | Splunk, Sentinel |
| JA4 from packet captures and Zeek | [`network/tshark-zeek-ja4.md`](network/tshark-zeek-ja4.md) | tshark, Zeek |

## How each file is laid out

Every query set follows the same structure so it can be reviewed quickly:

1. **Goal:** the behavior being hunted
2. **Data needed:** the telemetry or log source
3. **ATT&CK:** technique mapping
4. **Query:** the template
5. **False positives and tuning:** what normally triggers it and how to cut noise
6. **Next steps:** what to pivot on when it fires

## Related write-ups

The reasoning behind these queries is written up in my articles:

- [ClickFix and CrowdStrike hunting](https://hahashem.github.io/article.html?slug=dfir-clickfix-investigation)
- [Hunting distributed attacks with JA4](https://hahashem.github.io/article.html?slug=ja4-fingerprint-hunting)
- [DFIR case study: phishing to lateral movement](https://hahashem.github.io/article.html?slug=dfir-phishing-to-lateral-movement)

## Contributing and feedback

Found a field that is wrong for your sensor version, or a better filter? Open an issue or pull request with what you changed and why.

## License

[MIT](LICENSE)
