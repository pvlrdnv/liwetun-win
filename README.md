# LiWeTun

Самостоятельный клиент подключений для Windows. Отдельный репозиторий,
без общей истории, runtime или зависимостей от checkout LikeWeb.

Статус: начальный клиентский срез, **не готовый сетевой клиент**.
UI, импорт ссылок, модель обновления подписки и безопасный экспорт диагностики
разрабатываются локально. Нативная служба и сетевые ядра пока не подключены.
Кнопка подключения не имитирует успешное соединение.

## Разработка

Зафиксированная отправная точка: Flutter 3.38.10 / Dart 3.10.9.

```sh
flutter pub get
flutter analyze
flutter test
```

На Windows с Visual Studio Desktop development with C++:

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
