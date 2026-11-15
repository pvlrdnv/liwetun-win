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

Real imported names appear only after an explicit user action. All imports
remain in memory for this development slice. Connection CTA explains that the
Windows module is not yet integrated. It never changes to connected.

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
upload or support messaging. Clear-log action removes current in-memory events.
Persistent rotated journal is a later step; limits are explicit in STATUS.

## Accessibility and states

Light/dark follows OS; Material controls, keyboard focus, descriptive tooltips,
scrolling and compact navigation. Required future native states: disconnected,
connecting, checking internet, connected, recovering, error. Only disconnected
and unavailable are currently backed by actual behavior. No fabricated metrics.
