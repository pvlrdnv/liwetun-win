# LiWeTun working rules

Scope: only this independent client repository. Sibling LikeWeb repositories
are reference-only; do not edit them, production state or their Git metadata.
No production connections, live credentials, deployment or server changes.

Use a feature branch. Do not push to main. Remote: private GitHub repository
pvlrdnv/liwetun-win; no word VPN in repository name or GitHub description.
Never commit personal connection URIs, tokens, PEMs, configs or raw core output.

Read README.md, docs/ADR-001.md and docs/STATUS.md before implementation.
Do not equate a process start with a working tunnel. Keep unimplemented native
capabilities visibly unavailable. WSL tests do not establish Windows readiness.
Use only synthetic fixtures. Closed typed diagnostic events, no free-form logs.
Update docs/STATUS.md after substantive work with actual checks and limitations.
