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

Targets: Windows 10 x64 and Windows 11 x64, qualified separately. Server 2022 CI
is not desktop acceptance. The owner's development device has a corporate tunnel:
keep it operating; do not install a LiWeTun service/driver, alter trust stores,
firewall, DNS or routes on that device. Use disposable CI for network experiments.
Manual owner acceptance will use a separate Windows 10 PC and a prepared signed
package/report workflow, without a development toolchain or temporary CI roots.
