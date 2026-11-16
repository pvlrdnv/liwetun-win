# LiWeTun

Самостоятельный клиент подключений для Windows 10/11 x64. Отдельный репозиторий,
без общей истории, runtime или зависимостей от checkout LikeWeb.

Статус: начальный клиентский срез, **не готовый сетевой клиент**.
UI, нативный разбор TrustTunnel-ссылок, модель обновления подписки и безопасный
экспорт диагностики реализованы как начальный срез. Windows C++/Rust-мост собран
и проверен через настоящий Flutter-канал на Windows-runner.
Добавлены подписанная Windows-служба и канал управления из приложения.
Полный SDK собран в CI; служба с настоящим SDK прошла 15 проверок на Windows.
На ограниченном Windows CI проверены HTTPS/DNS через TUN по HTTP/2 и HTTP/3
и очистка после аварий. Выпускной установщик ещё не подготовлен.
Кнопка подключения не имитирует успешное соединение.
Профили и ограниченный журнал сохраняются через защиту Windows; восстановление
и очистка проверены через настоящие каналы приложения в Windows CI.

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
Для Windows реализовано защищённое хранение ссылок через пользовательский DPAPI;
нативные проверки и восстановление профилей через GUI прошли Windows CI.
При ошибке хранилища интерфейс явно сообщает о работе только в памяти.
Автозагрузка подписки и реальные HTTP-запросы пока не включены.

## Документы

- [Архитектура и границы](docs/ADR-001.md)
- [Проект контракта подписки](docs/SUBSCRIPTION_V1.md)
- [Экраны и состояния](docs/UI.md)
- [Приёмка на Windows](docs/WINDOWS_ACCEPTANCE.md)
- [Совместимость и проверка на втором ПК](docs/WINDOWS_COMPATIBILITY.md)
- [Подготовка сценария проверки без среды разработки](docs/OWNER_WINDOWS_TEST.md)
- [Нативный импорт и его границы](docs/NATIVE_IMPORT.md)
- [Windows-служба и границы проверки](docs/WINDOWS_SERVICE.md)
- [Приёмка реального TUN-трафика](docs/TUN_NETWORK_ACCEPTANCE.md)
- [Защищённое хранение профилей](docs/PROFILE_STORAGE.md)
- [Хранение и ограничение журнала](docs/JOURNAL_STORAGE.md)
- [Зависимости и лицензионный комплект](docs/DEPENDENCY_CLOSURE.md)
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
