# LiWeTun — first three screens

The implementation is a desktop Flutter shell, not a website.
Initial state contains no synthetic servers presented as personal servers.

## Main

```text
LiWeTun        Главная / Серверы / Поддержка

ЗАЩИЩЁННОЕ ПОДКЛЮЧЕНИЕ
Ваш интернет. Ваш выбор.

       [power]       Не подключено
                     Добавьте персональную ссылку

[Автоматически — будет доступно после проверки ядра]
[Добавить подключение]
```

Imported profiles are restored from the protected current-user cache without
automatic connection; new profiles require explicit import. Storage status
distinguishes loading/saving/saved and memory-only failure. Connection CTA dispatches start/stop to the Windows service channel. Unsigned
workspace builds cannot access the service. Tunnel-ready is labelled separately
from verified Internet; unknown outcomes remain uncertain and permit stop.

## Servers

Paste/import dialog with obscured input, no autofill and no raw parse exception.
TrustTunnel direct and QR links are structurally classified and retained opaque
until the SDK decodes them. VLESS/HY2 authority and TLS settings are validated
for the supported subset. HTTPS URL is a pending subscription source, never a
ready server. Server list includes search, selection, protocol in advanced
details, and separate unknown service/entitlement observations.

## Support

Closed structured local events; preview archive composition and time range;
user chooses where to save ZIP. Archive contains summary.json and events.jsonl,
never profile names, URLs, addresses, configs or raw exceptions. No automatic
upload or support messaging. Clear-log action removes current events and requests
protected disk deletion. Storage status distinguishes pending, confirmed and
failed writes/clear; history is bounded to seven days/1000 events. Windows GUI
persistence verification passed; see JOURNAL_STORAGE.md.

## Accessibility and states

Light/dark follows OS; Material controls, keyboard focus, descriptive tooltips,
scrolling and compact navigation. Required future native states: disconnected,
connecting, checking internet, connected, recovering, error. The service channel now backs disconnected, connecting, tunnel-ready, recovering
and error; checking Internet/connected remain unavailable until route-bound
traffic qualification exists. No fabricated metrics.
