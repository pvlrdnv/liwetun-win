# LiWeTun

Самостоятельный клиент подключений для Windows 10/11 x64. Отдельный репозиторий,
без общей истории, runtime или зависимостей от checkout LikeWeb.

Статус: начальный клиентский срез, **не готовый сетевой клиент**.
UI, нативный разбор TrustTunnel-ссылок, модель обновления подписки и безопасный
экспорт диагностики реализованы как начальный срез. Windows C++/Rust-мост собран
и проверен через настоящий Flutter-канал на Windows-runner.
Добавлены подписанная Windows-служба и канал управления из приложения.
Полный SDK собран в CI; служба с настоящим SDK прошла 15 проверок на Windows.
Реальная передача трафика через TUN и выпускной установщик ещё не проверены.
Кнопка подключения не имитирует успешное соединение.

## Разработка

Зафиксированная отправная точка: Flutter 3.38.10 / Dart 3.10.9.

```sh
flutter pub get
flutter analyze
flutter test
```

На Windows с Visual Studio Desktop development with C++ и Rust 1.95.0
(Cargo должен быть в PATH; версия закреплена в rust-toolchain.toml):

```powershell
flutter doctor -v
flutter run -d windows
flutter build windows --release
```

Сборка оболочки не является выпуском: подпись, SDK, служба, маршрутизация,
DNS/IPv6 и приёмка на чистой Windows остаются отдельными gates.
Импортированные ссылки хранятся только в памяти: после закрытия нужно
импортировать заново. Это временная граница до Windows DPAPI storage.
Автозагрузка подписки и реальные HTTP-запросы пока не включены.

## Документы

- [Архитектура и границы](docs/ADR-001.md)
- [Проект контракта подписки](docs/SUBSCRIPTION_V1.md)
- [Экраны и состояния](docs/UI.md)
- [Приёмка на Windows](docs/WINDOWS_ACCEPTANCE.md)
- [Совместимость и проверка на втором ПК](docs/WINDOWS_COMPATIBILITY.md)
- [Нативный импорт и его границы](docs/NATIVE_IMPORT.md)
- [Windows-служба и границы проверки](docs/WINDOWS_SERVICE.md)
- [Состояние разработки](docs/STATUS.md)

Для получения превью настоящих Flutter-экранов (без запуска нативного ядра):

```sh
flutter test tools/render_previews_test.dart --dart-define=PREVIEW_FONT=<flutter-sdk>/bin/cache/artifacts/material_fonts/Roboto-Regular.ttf
```

Изображения записываются в `build/previews/` и не коммитятся. Векторный источник
иконки: `assets/brand/liwetun.svg`; ICO воспроизводится командой
`python3 tools/generate_icon.py` без внешних пакетов.

Реальные credentials, конфигурации и production-данные сюда не переносить.
Публикация и изменение серверных репозиториев LikeWeb в текущий этап не входят.
