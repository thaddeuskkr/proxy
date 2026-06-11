# tkProxyConfig

Generate proxy rule files from upstream GitHub-hosted `.list` sources.

## Merge lists

Add files to `source/`. Each file should contain one GitHub file URL per line. Then, run:

```sh
python3 merge_lists.py
```

The script uses the GitHub repository contents API, keeps each unique rule once,
and removes source comments by default. Set `GITHUB_TOKEN` to raise GitHub API
rate limits.

Add local rules to `defaults/` with the same filename when you want rules that
are not fetched from URLs. For example, `defaults/proxy.list` is prepended to
the fetched rules from `source/proxy.list` before writing `output/proxy.list`.
Default rules stay at the start of the generated file, and duplicate remote
rules are removed after the default copy.

In `defaults/*.list` or `source/*.list`, add a `# {END}` marker to treat every
rule or URL below it as if it ended with `# {PIN-END}`.

Add `# {PIN-START}` or `# {PIN-END}` at the end of a `defaults/*.list` rule to
pin that rule to the start or end of the generated file. Add the same marker to
a URL line in `source/*.list` to pin all resolved rules from that URL. Pinned
rules are not deduped, pruned, converted by optimizer-only passes, or
heuristically reordered.

By default, the script also optimizes generated lists:

- removes exact duplicate rules after normalization
- removes CIDR ranges already covered by broader CIDRs with the same options
- converts simple wildcard, keyword, and regex domain rules to `DOMAIN-SUFFIX`
- removes exact `DOMAIN` rules already covered by a matching `DOMAIN-SUFFIX`
- reorders rules so service-specific and cheap rule types are earlier than huge
  catch-all sources and expensive regex rules

URLs whose path contains a file or folder ending in `_Domain` are converted into
normal Shadowrocket rules and merged into the same output file:

```txt
.example.com -> DOMAIN-SUFFIX,example.com
example.com -> DOMAIN-SUFFIX,example.com
192.0.2.1 -> IP-CIDR,192.0.2.1/32,no-resolve
*.example.com -> DOMAIN-WILDCARD,*.example.com
regexp:^https?://example\.com -> URL-REGEX,^https?://example\.com
```

Use `--bare-domain-rule domain` if you want bare `_Domain` entries converted to
`DOMAIN,example.com` instead of the default `DOMAIN-SUFFIX,example.com`.

## Reports

Each run writes:

```txt
output/report.json
output/report.md
```

The reports include source counts, fetched and final line counts, removed rule
counts, conversion counts, rule type summaries, largest sources, and warning
examples for complex rules that were preserved.
