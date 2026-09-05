# freenginx

[![build](https://github.com/grumpylabs/freenginx/actions/workflows/build.yml/badge.svg)](https://github.com/grumpylabs/freenginx/actions/workflows/build.yml)

A read-only Git mirror of [freenginx](https://freenginx.org/), Maxim Dounin's fork of nginx.

## Upstream lives in Mercurial

freenginx is developed in hg, not git. This mirror exists so the source is reachable
from GitHub — but upstream is always the authority:

| | |
| --- | --- |
| Project site | <https://freenginx.org/> |
| **Upstream hg repo** | <https://freenginx.org/hg/nginx> |
| Test suite (separate hg repo) | <https://freenginx.org/hg/nginx-tests> |

Send patches and bug reports upstream, not here.

## How the mirror works

The mirror is refreshed by a sync process that pulls the upstream hg repo, rsyncs its
working tree over this one, and pushes the result. That tooling lives outside this
repository. The upstream revision each commit corresponds to is recorded in
`.last_hg_sync` and in the commit message.

This is a **snapshot** mirror, not a history conversion — every upstream changeset since
the previous sync collapses into a single git commit. So:

- Good for: building, reading, and tracking current source.
- Not good for: `git log`, `git blame` or `git bisect` against upstream history. Use the
  hg repo for that.

`README.md`, `.gitignore` and `.github/` do not exist upstream, so the sync is configured
to leave them in place; otherwise its `rsync --delete` would remove them on every run.

## Sniff test

Because the mirror is an rsync snapshot, a truncated or corrupt sync would otherwise land
silently — the push would look identical to a good one. So every push to `main` (plus a
weekly run) triggers a GitHub Actions job that verifies the tree is actually usable:

- configures and builds with `--with-http_ssl_module --with-http_v2_module
  --with-http_v3_module --with-stream`, on both Linux and macOS
- runs `nginx -t` against the shipped default config
- starts the binary and serves real requests: asserts `200` and a `Server: freenginx/`
  header over plain HTTP, and `200` over TLS with HTTP/2 negotiated

It is a build-and-serve sanity check, not a correctness suite — for that, see the upstream
`nginx-tests` repo linked above. If the badge is green, the mirrored source compiles and
runs.

Enjoy!
