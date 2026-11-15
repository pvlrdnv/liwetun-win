import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';

import 'app_controller.dart';
import 'brand_mark.dart';
import 'diagnostics/journal.dart';
import 'domain/import_link.dart';

const _green = Color(0xFF84D5B5);
const _ink = Color(0xFF112B27);

class LiWeTunApp extends StatelessWidget {
  const LiWeTunApp({super.key, required this.controller});
  final AppController controller;

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'LiWeTun',
    debugShowCheckedModeBanner: false,
    theme: _theme(Brightness.light),
    darkTheme: _theme(Brightness.dark),
    home: _Home(controller: controller),
  );

  ThemeData _theme(Brightness brightness) {
    final dark = brightness == Brightness.dark;
    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      colorScheme: ColorScheme.fromSeed(
        seedColor: _ink,
        brightness: brightness,
      ),
      scaffoldBackgroundColor: dark
          ? const Color(0xFF101A18)
          : const Color(0xFFF4F6F1),
      cardTheme: CardThemeData(
        elevation: 0,
        color: dark ? const Color(0xFF1B2925) : Colors.white,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
      ),
      inputDecorationTheme: InputDecorationTheme(
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(14)),
      ),
    );
  }
}

class _Home extends StatefulWidget {
  const _Home({required this.controller});
  final AppController controller;
  @override
  State<_Home> createState() => _HomeState();
}

class _HomeState extends State<_Home> {
  int _page = 0;
  String _search = '';
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_changed);
  }

  void _changed() => setState(() {});

  @override
  void dispose() {
    widget.controller.removeListener(_changed);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final wide = constraints.maxWidth >= 760;
      return Scaffold(
        body: SafeArea(
          child: Row(
            children: [
              if (wide) _navigation(),
              Expanded(
                child: Column(
                  children: [
                    Padding(
                      padding: const EdgeInsets.fromLTRB(28, 20, 28, 8),
                      child: SizedBox(
                        width: double.infinity,
                        child: Wrap(
                          alignment: wide
                              ? WrapAlignment.end
                              : WrapAlignment.spaceBetween,
                          crossAxisAlignment: WrapCrossAlignment.center,
                          spacing: 16,
                          runSpacing: 8,
                          children: [
                            if (!wide) const _Brand(),
                            const Chip(label: Text('Ранняя версия · 0.1')),
                          ],
                        ),
                      ),
                    ),
                    Expanded(
                      child: SingleChildScrollView(
                        padding: EdgeInsets.all(wide ? 32 : 20),
                        child: Align(
                          alignment: Alignment.topCenter,
                          child: ConstrainedBox(
                            constraints: const BoxConstraints(maxWidth: 900),
                            child: switch (_page) {
                              0 => _mainPage(),
                              1 => _serversPage(),
                              _ => _supportPage(),
                            },
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        bottomNavigationBar: wide
            ? null
            : NavigationBar(
                selectedIndex: _page,
                onDestinationSelected: (page) => setState(() => _page = page),
                destinations: const [
                  NavigationDestination(
                    icon: Icon(Icons.home_outlined),
                    label: 'Главная',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.public),
                    label: 'Серверы',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.help_outline),
                    label: 'Поддержка',
                  ),
                ],
              ),
      );
    },
  );

  Widget _navigation() => Container(
    width: 216,
    decoration: BoxDecoration(
      border: Border(
        right: BorderSide(
          color: Theme.of(context).dividerColor.withValues(alpha: .15),
        ),
      ),
    ),
    child: Column(
      children: [
        const Padding(
          padding: EdgeInsets.symmetric(vertical: 36),
          child: _Brand(),
        ),
        const SizedBox(height: 24),
        for (final (index, icon, label) in [
          (0, Icons.home_outlined, 'Главная'),
          (1, Icons.public, 'Серверы'),
          (2, Icons.help_outline, 'Поддержка'),
        ])
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 4),
            child: ListTile(
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(14),
              ),
              selected: _page == index,
              selectedTileColor: _green.withValues(alpha: .2),
              leading: Icon(icon),
              title: Text(label),
              onTap: () => setState(() => _page = index),
            ),
          ),
        const Spacer(),
        const Padding(
          padding: EdgeInsets.all(24),
          child: Text(
            'Спокойно.\nНа своей стороне.',
            style: TextStyle(fontSize: 12, height: 1.6),
          ),
        ),
      ],
    ),
  );

  Widget _heading(String eyebrow, String title, String subtitle) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text(
        eyebrow,
        style: const TextStyle(
          fontSize: 11,
          fontWeight: FontWeight.w700,
          letterSpacing: 2,
        ),
      ),
      const SizedBox(height: 12),
      Text(
        title,
        style: const TextStyle(
          fontSize: 32,
          height: 1.15,
          fontWeight: FontWeight.w600,
          letterSpacing: -1,
        ),
      ),
      const SizedBox(height: 12),
      Text(subtitle, style: const TextStyle(fontSize: 14, height: 1.6)),
      const SizedBox(height: 28),
    ],
  );

  Widget _mainPage() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      _heading(
        'ЛИЧНОЕ ПОДКЛЮЧЕНИЕ',
        'Ваш интернет.\nВаш выбор.',
        'Добавьте персональную ссылку из бота или кабинета Like Web.',
      ),
      Card(
        color: _ink,
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Row(
                children: [
                  Icon(Icons.circle, size: 8, color: Colors.white54),
                  SizedBox(width: 8),
                  Text(
                    'НЕ ПОДКЛЮЧЕНО',
                    style: TextStyle(
                      color: Colors.white70,
                      fontSize: 11,
                      letterSpacing: 2,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 36),
              Center(
                child: IconButton.filled(
                  tooltip: 'Проверить готовность подключения',
                  style: IconButton.styleFrom(
                    backgroundColor: _green,
                    foregroundColor: _ink,
                    padding: const EdgeInsets.all(28),
                  ),
                  iconSize: 52,
                  onPressed: _unavailable,
                  icon: const Icon(Icons.power_settings_new),
                ),
              ),
              const SizedBox(height: 28),
              Center(
                child: Text(
                  widget.controller.selected?.title ??
                      'Начните с персональной ссылки',
                  style: const TextStyle(color: Colors.white, fontSize: 18),
                ),
              ),
              const SizedBox(height: 12),
              const Center(
                child: Text(
                  'Модуль подключения Windows ещё не интегрирован.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.white70, height: 1.5),
                ),
              ),
              const SizedBox(height: 28),
              const Divider(color: Colors.white24),
              const ListTile(
                contentPadding: EdgeInsets.zero,
                leading: Icon(Icons.auto_awesome_outlined, color: _green),
                title: Text(
                  'Автоматический выбор',
                  style: TextStyle(color: Colors.white),
                ),
                subtitle: Text(
                  'Будет доступен после проверки ядра',
                  style: TextStyle(color: Colors.white60),
                ),
              ),
            ],
          ),
        ),
      ),
      const SizedBox(height: 20),
      FilledButton.icon(
        onPressed: _import,
        icon: const Icon(Icons.add),
        label: const Text('Добавить подключение'),
      ),
      const SizedBox(height: 16),
      const Text(
        'Ссылки сохраняются только до закрытия приложения.',
        style: TextStyle(fontSize: 12),
      ),
    ],
  );

  Widget _serversPage() {
    final connections = widget.controller.connections
        .where(
          (item) => item.title.toLowerCase().contains(_search.toLowerCase()),
        )
        .toList();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _heading(
          'ВАШИ НАПРАВЛЕНИЯ',
          'Подключения',
          'Персональные ссылки и подписки — в одном месте.',
        ),
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            FilledButton.icon(
              onPressed: _import,
              icon: const Icon(Icons.add),
              label: const Text('Добавить ссылку'),
            ),
            OutlinedButton.icon(
              onPressed: () => _message(
                'Обновление подписки ещё не подключено. Серверный формат согласуется отдельно.',
              ),
              icon: const Icon(Icons.refresh),
              label: const Text('Обновить подписку'),
            ),
          ],
        ),
        const SizedBox(height: 20),
        TextField(
          decoration: const InputDecoration(
            prefixIcon: Icon(Icons.search),
            hintText: 'Найти подключение',
          ),
          onChanged: (value) => setState(() => _search = value),
        ),
        const SizedBox(height: 20),
        if (connections.isEmpty)
          const Card(
            child: Padding(
              padding: EdgeInsets.all(28),
              child: Text(
                'Пока ничего нет. Добавьте ссылку, полученную в Like Web.',
              ),
            ),
          ),
        for (final connection in connections)
          Card(
            child: ListTile(
              contentPadding: const EdgeInsets.symmetric(
                horizontal: 20,
                vertical: 12,
              ),
              leading: Icon(
                connection.link.kind == ImportKind.subscription
                    ? Icons.sync
                    : Icons.public,
              ),
              title: Text(connection.title),
              subtitle: Text(
                connection.link.kind == ImportKind.subscription
                    ? 'Ожидает загрузки · обновлений ещё не было'
                    : 'Доступность и право доступа не проверены',
              ),
              trailing: connection.link.kind == ImportKind.subscription
                  ? null
                  : Icon(
                      widget.controller.selectedId == connection.link.localId
                          ? Icons.radio_button_checked
                          : Icons.radio_button_off,
                    ),
              onTap: () => widget.controller.select(connection),
            ),
          ),
        const SizedBox(height: 16),
        ExpansionTile(
          title: const Text('Технические детали'),
          children: [
            for (final connection in connections)
              ListTile(
                title: Text(connection.title),
                subtitle: Text(
                  connection.link.protocol?.name ?? 'HTTPS-подписка',
                ),
              ),
            const ListTile(
              title: Text('Состояние модулей'),
              subtitle: Text('TrustTunnel / Hysteria2 / Xray не интегрированы'),
            ),
          ],
        ),
      ],
    );
  }

  Widget _supportPage() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      _heading(
        'ПОМОЩЬ РЯДОМ',
        'Разберёмся вместе.',
        'Сохраните технический отчёт и передайте его поддержке самостоятельно.',
      ),
      Card(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Icon(Icons.description_outlined, size: 32),
              const SizedBox(height: 16),
              const Text(
                'Отчёт о работе приложения',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 12),
              Text(
                'Событий в текущем сеансе: ${widget.controller.journal.events.length}. До 1000 событий в памяти.',
              ),
              const SizedBox(height: 12),
              const Text(
                'Состав: версия, период и очищенные события. Адреса, ссылки, ключи и история посещений не включаются.',
              ),
              const SizedBox(height: 20),
              FilledButton.icon(
                onPressed: _saving ? null : _export,
                icon: const Icon(Icons.save_alt),
                label: const Text('Сохранить отчёт для поддержки'),
              ),
              TextButton(
                onPressed: widget.controller.clearJournal,
                child: const Text('Удалить локальный журнал'),
              ),
            ],
          ),
        ),
      ),
      const SizedBox(height: 20),
      const Text(
        'Журнал текущего сеанса',
        style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
      ),
      for (final event in widget.controller.journal.events.reversed.take(15))
        ListTile(
          dense: true,
          title: Text(event.event.name),
          subtitle: Text(
            '${event.at.toUtc().toIso8601String()} · ${event.reason.name}',
          ),
        ),
      const SizedBox(height: 20),
      const Text(
        'Автозапуск, трей и автоподключение появятся после интеграции и проверки службы Windows.',
      ),
    ],
  );

  Future<void> _import() async {
    final text = TextEditingController();
    String? result;
    try {
      result = await showDialog<String>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Добавить персональную ссылку'),
          content: SizedBox(
            width: 460,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Вставьте ссылку подключения или HTTPS-подписки. Она останется только в памяти приложения.',
                ),
                const SizedBox(height: 20),
                TextField(
                  controller: text,
                  autofocus: true,
                  obscureText: true,
                  enableSuggestions: false,
                  autocorrect: false,
                  maxLength: 8192,
                  decoration: const InputDecoration(
                    labelText: 'Персональная ссылка',
                    counterText: '',
                  ),
                  onSubmitted: (_) => Navigator.pop(context, text.text),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Отмена'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, text.text),
              child: const Text('Добавить'),
            ),
          ],
        ),
      );
    } finally {
      // Route exit animation can still access the field; dispose after unmount.
      await Future<void>.delayed(const Duration(milliseconds: 300));
      text.dispose();
    }
    if (result != null && mounted) _message(widget.controller.import(result));
  }

  void _unavailable() {
    widget.controller.connectionUnavailable();
    _message(
      'Для подключения нужен модуль Windows. Он пока не интегрирован; сетевые настройки не менялись.',
    );
  }

  Future<void> _export() async {
    setState(() => _saving = true);
    try {
      // Freeze bytes before preview so the selected range matches the archive.
      final journal = widget.controller.journal;
      final preview = journal.preview;
      final bytes = journal.exportZip();
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Состав отчёта'),
          content: Text(
            'summary.json и events.jsonl\nКоличество событий: ${preview.count}\n'
            'С: ${preview.start?.toUtc().toIso8601String() ?? "нет событий"}\n'
            'По: ${preview.end?.toUtc().toIso8601String() ?? "нет событий"}\n\n'
            'Ссылки, адреса и ключи не включены. Автоматической отправки нет.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Отмена'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Выбрать файл'),
            ),
          ],
        ),
      );
      if (confirmed != true || !mounted) return;
      final location = await getSaveLocation(
        suggestedName: 'liwetun-support.zip',
        acceptedTypeGroups: const [
          XTypeGroup(label: 'ZIP', extensions: ['zip']),
        ],
      );
      if (location == null) return;
      await File(location.path).writeAsBytes(bytes, flush: true);
      journal.record(EventId.reportSaved);
      if (mounted) {
        _message('Отчёт сохранён. Вы можете передать его поддержке.');
      }
    } catch (_) {
      widget.controller.journal.record(
        EventId.reportSaveFailed,
        reason: ReasonCode.ioFailure,
      );
      if (mounted) {
        _message(
          'Не удалось сохранить отчёт. Выберите доступную папку и попробуйте снова.',
        );
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  void _message(String text) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
  }
}

class _Brand extends StatelessWidget {
  const _Brand();
  @override
  Widget build(BuildContext context) => const Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      BrandMark(size: 32),
      SizedBox(width: 10),
      Text(
        'LiWeTun',
        style: TextStyle(
          fontSize: 23,
          fontWeight: FontWeight.w700,
          letterSpacing: -1,
        ),
      ),
    ],
  );
}
