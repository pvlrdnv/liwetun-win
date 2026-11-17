import 'package:flutter/services.dart';
import 'package:flutter/material.dart' show OutlinedButton;
import 'dart:io';
import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:liwetun/app.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/native/trusttunnel.dart';
import 'package:liwetun/native/service.dart';
import 'package:liwetun/native/storage.dart';
import 'package:liwetun/domain/profile_cache.dart';
import 'package:liwetun/domain/subscription.dart';
import 'package:liwetun/network/subscription_transport.dart';
import 'package:liwetun/native/environment.dart';
import 'package:liwetun/native/desktop.dart';
import 'package:liwetun/diagnostics/journal.dart';

final class _RealHttp extends HttpOverrides {}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('actual Windows C++ channel and official decoder, no network', (
    tester,
  ) async {
    final controller = AppController();
    addTearDown(controller.dispose);
    await tester.pumpWidget(LiWeTunApp(controller: controller));
    final environment = await const WindowsEnvironment().read();
    expect(environment.major, 10);
    expect(environment.build, greaterThanOrEqualTo(20348));
    expect(environment.appArchitecture, AppArchitecture.x64);
    final cli = await Process.run(Platform.resolvedExecutable, [
      '--service-status',
    ]);
    expect(
      cli.exitCode,
      9,
    ); // Unsigned workspace is rejected before SCM/pipe access.
    expect(jsonDecode(cli.stdout as String), {
      'code': 9,
      'state': null,
      'runtime_ready': null,
      'core_state': null,
    });
    final capabilities = await WindowsTrustTunnel.channel
        .invokeMapMethod<String, dynamic>('capabilities');
    expect(capabilities?['canInspect'], true);
    expect(capabilities?['canConnect'], false);
    expect(capabilities?['abiVersion'], 1);
    expect(
      capabilities?['decoderRevision'],
      '48f424c0874eb6f6374ee84492c5cd55aa04dca9',
    );
    for (final (uri, transport) in [
      (const String.fromEnvironment('SYNTHETIC_TT_HTTP2'), 2),
      (const String.fromEnvironment('SYNTHETIC_TT_HTTP3'), 3),
    ]) {
      expect(
        uri.isNotEmpty,
        true,
        reason: 'Generate synthetic fixture defines first',
      );
      final inspection = await const WindowsTrustTunnel().inspect(
        SecretLink(uri),
      );
      expect(inspection.status, NativeImportStatus.accepted);
      expect(inspection.transport, transport);
      await controller.importValidated(uri);
    }
    const insecure = String.fromEnvironment('SYNTHETIC_TT_INSECURE');
    expect(insecure.isNotEmpty, true);
    expect(
      (await const WindowsTrustTunnel().inspect(
        const SecretLink(insecure),
      )).status,
      NativeImportStatus.insecure,
    );
    expect(
      (await const WindowsTrustTunnel().inspect(
        const SecretLink('tt://?SYNTHETIC_NATIVE_PRIVATE_CANARY'),
      )).status,
      NativeImportStatus.malformed,
    );
    await tester.pumpAndSettle();
    expect(find.text('НЕ ПОДКЛЮЧЕНО'), findsOneWidget);
    expect(controller.connections.length, 2);
    // This unsigned workspace build must fail before SCM/pipe side effects.
    // Exercise the actual worker and platform-thread result delivery.
    const service = WindowsService();
    for (final request in [service.query, service.stop]) {
      final status = await request();
      expect(status.code, ServiceCode.untrustedInstallation);
      expect(status.runtimeReady, false);
      expect(status.coreState, isNull);
    }
    final start = await service.start(
      const SecretLink(String.fromEnvironment('SYNTHETIC_TT_HTTP2')),
    );
    expect(start.code, ServiceCode.untrustedInstallation);
    await expectLater(
      WindowsTrustTunnel.channel.invokeMethod<void>(
        'arbitraryPrivilegedCommand',
      ),
      throwsA(isA<MissingPluginException>()),
    );
  });
  testWidgets(
    'actual user DPAPI channel restores profiles without connecting',
    (tester) async {
      // This test writes synthetic profiles only on a disposable runner.
      expect(Platform.environment['GITHUB_ACTIONS'], 'true');
      const storage = WindowsStorage();
      final initial = await storage.load();
      expect(initial.code, StorageCode.missing);
      String revision = '';
      try {
        final link = parseLink(
          const String.fromEnvironment('SYNTHETIC_TT_HTTP3'),
        );
        final saved = await storage.save(
          ProfileCache(links: [link], selectedId: link.localId).encode(),
          '',
        );
        expect(saved.code, StorageCode.ok);
        revision = saved.revision;
        final conflict = await storage.save('{}', '');
        expect(conflict.code, StorageCode.conflict);
        final controller = AppController();
        addTearDown(controller.dispose);
        await controller.initializeStorage();
        expect(controller.storageState, ProfileStorageState.saved);
        expect(controller.selected?.link.localId, link.localId);
        expect(
          controller.selected?.inspection?.status,
          NativeImportStatus.accepted,
        );
        expect(controller.stopPossible, false);
        final loaded = await storage.load();
        expect(loaded.code, StorageCode.ok);
        expect(loaded.revision, revision);
        expect(
          ProfileCache.decode(loaded.payload!).links.single.secret.value,
          link.secret.value,
        );
        await expectLater(
          WindowsStorage.channel.invokeMethod<void>('save', {
            'path': 'PRIVATE_CANARY',
          }),
          throwsA(isA<PlatformException>()),
        );
        expect((await storage.load()).revision, revision);
      } finally {
        if (revision.isNotEmpty) {
          expect((await storage.clear(revision)).code, StorageCode.ok);
          expect((await storage.load()).code, StorageCode.missing);
        }
      }
    },
  );
  testWidgets(
    'actual protected journal restores and clears without touching profiles',
    (tester) async {
      expect(Platform.environment['GITHUB_ACTIONS'], 'true');
      const profiles = WindowsStorage();
      const storage = WindowsStorage.journal();
      expect((await profiles.load()).code, StorageCode.missing);
      expect((await storage.load()).code, StorageCode.missing);
      var profileRevision = '';
      final first = Journal()..record(EventId.appStarted);
      final second = Journal()..record(EventId.profilesRestored);
      addTearDown(first.disposePersistence);
      addTearDown(second.disposePersistence);
      try {
        final fixture = parseLink(
          const String.fromEnvironment('SYNTHETIC_TT_HTTP2'),
        );
        final profile = await profiles.save(
          ProfileCache(links: [fixture]).encode(),
          '',
        );
        expect(profile.code, StorageCode.ok);
        profileRevision = profile.revision;
        await first.initializePersistence(storage);
        expect((await storage.load()).code, StorageCode.ok);
        expect(first.persistenceState, JournalPersistenceState.saved);
        first.disposePersistence();
        await second.initializePersistence(storage);
        expect((await storage.load()).code, StorageCode.ok);
        expect(second.events.map((event) => event.event), [
          EventId.appStarted,
          EventId.profilesRestored,
        ]);
        second.clear();
        expect((await storage.load()).code, StorageCode.missing);
        expect(second.persistenceState, JournalPersistenceState.saved);
        expect((await profiles.load()).revision, profileRevision);
      } finally {
        first.disposePersistence();
        second.disposePersistence();
        final remaining = await storage.load();
        if (remaining.revision.isNotEmpty) {
          expect(
            (await storage.clear(remaining.revision)).code,
            StorageCode.ok,
          );
        }
        if (profileRevision.isNotEmpty) {
          expect((await profiles.clear(profileRevision)).code, StorageCode.ok);
        }
      }
    },
  );
  testWidgets(
    'actual DPAPI subscription cache preserves revoke and source binding without network',
    (tester) async {
      expect(Platform.environment['GITHUB_ACTIONS'], 'true');
      const storage = WindowsStorage();
      expect((await storage.load()).code, StorageCode.missing);
      final clock = DateTime.now().toUtc();
      final instant = DateTime.fromMillisecondsSinceEpoch(
        clock.millisecondsSinceEpoch ~/ 1000 * 1000,
        isUtc: true,
      );
      String stamp(DateTime time) =>
          time.toIso8601String().replaceFirst('.000Z', 'Z');
      final source = parseLink(
        'https://subscription.example.invalid/SYNTHETIC_PRIVATE',
      );
      String snapshot(int revision, {bool revoked = false}) => jsonEncode({
        'schema_version': 1,
        'revision': revision,
        'generated_at': stamp(instant),
        'valid_until': stamp(instant.add(const Duration(hours: 1))),
        'access_expires_at': stamp(instant.add(const Duration(days: 1))),
        'access': revoked ? 'revoked' : 'active',
        'complete': true,
        'profiles': revoked
            ? []
            : [
                {
                  'id': 'one',
                  'server_id': 'synthetic_one',
                  'name': 'Synthetic subscription',
                  'country': 'NL',
                  'protocol': 'trusttunnel',
                  'allowed': true,
                  'uri': const String.fromEnvironment('SYNTHETIC_TT_HTTP3'),
                },
              ],
        'revoked_profile_ids': [],
      });
      AppController? first, second;
      var created = false;
      try {
        final store = SubscriptionStore()..apply(snapshot(1), instant);
        final selection = ProfileCache.subscriptionSelectionId(
          source.localId,
          'one',
        );
        final saved = await storage.save(
          ProfileCache(
            links: [source],
            selectedId: selection,
            subscriptions: {source.localId: store},
          ).encode(),
          '',
        );
        expect(saved.code, StorageCode.ok);
        created = true;
        first = AppController();
        await first.initializeStorage();
        expect(first.storageState, ProfileStorageState.saved);
        expect(first.connections.length, 2);
        expect(first.selected?.selectionId == selection, isTrue);
        expect(first.selected?.inspection?.status, NativeImportStatus.accepted);
        expect(first.stopPossible, isFalse);
        await first.applySubscriptionSnapshot(
          source.localId,
          snapshot(2, revoked: true),
        );
        for (
          var attempt = 0;
          attempt < 30 && first.storageState == ProfileStorageState.saving;
          attempt++
        ) {
          await tester.pump(const Duration(milliseconds: 100));
        }
        expect(first.storageState, ProfileStorageState.saved);
        expect(first.selected, isNull);
        final loaded = await storage.load();
        expect(loaded.code, StorageCode.ok);
        final cache = ProfileCache.decode(loaded.payload!);
        expect(cache.subscriptions[source.localId]!.revision, 2);
        expect(cache.subscriptions[source.localId]!.access, Access.revoked);
        first.dispose();
        first = null;
        second = AppController();
        await second.initializeStorage();
        expect(second.connections.length, 1);
        expect(second.selected, isNull);
        expect(second.stopPossible, isFalse);
        await second.applySubscriptionSnapshot(source.localId, snapshot(1));
        expect(second.connections.length, 1);
        expect(second.selected, isNull);
        expect((await storage.load()).revision == loaded.revision, isTrue);
      } finally {
        first?.dispose();
        second?.dispose();
        if (created) {
          final remaining = await storage.load();
          expect(remaining.code, StorageCode.ok);
          expect(
            (await storage.clear(remaining.revision)).code,
            StorageCode.ok,
          );
          expect((await storage.load()).code, StorageCode.missing);
        }
      }
    },
  );
  testWidgets(
    'actual HTTPS refresh UI applies and revokes a DPAPI subscription without tunnel',
    (tester) async {
      expect(Platform.environment['GITHUB_ACTIONS'], 'true');
      const storage = WindowsStorage();
      expect((await storage.load()).code, StorageCode.missing);
      final directory =
          Platform.environment['LIWETUN_SUBSCRIPTION_TLS_FIXTURE'];
      expect(directory != null, isTrue);
      final certificate = '$directory/cert.pem';
      final serverContext = SecurityContext(withTrustedRoots: false)
        ..useCertificateChain(certificate)
        ..usePrivateKey('$directory/key.pem');
      final trusted = SecurityContext(withTrustedRoots: false)
        ..setTrustedCertificates(certificate);
      final server = await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4,
        0,
        serverContext,
      );
      var requests = 0;
      var revoked = false;
      final wall = DateTime.now().toUtc();
      final instant = DateTime.fromMillisecondsSinceEpoch(
        wall.millisecondsSinceEpoch ~/ 1000 * 1000,
        isUtc: true,
      );
      var clock = instant;
      String stamp(DateTime value) =>
          value.toIso8601String().replaceFirst('.000Z', 'Z');
      server.listen((request) async {
        requests++;
        try {
          request.response.headers.contentType = ContentType.json;
          request.response.write(
            jsonEncode({
              'schema_version': 1,
              'revision': revoked ? 2 : 1,
              'generated_at': stamp(instant),
              'valid_until': stamp(instant.add(const Duration(hours: 1))),
              'access_expires_at': stamp(instant.add(const Duration(days: 1))),
              'access': revoked ? 'revoked' : 'active',
              'complete': true,
              'profiles': revoked
                  ? []
                  : [
                      {
                        'id': 'one',
                        'server_id': 'synthetic_https',
                        'name': 'Synthetic HTTPS subscription',
                        'country': 'NL',
                        'protocol': 'trusttunnel',
                        'allowed': true,
                        'uri': const String.fromEnvironment(
                          'SYNTHETIC_TT_HTTP2',
                        ),
                      },
                    ],
              'revoked_profile_ids': [],
            }),
          );
          await request.response.close();
        } catch (_) {}
      }, onError: (_) {});
      final transport = HttpSubscriptionTransport(
        resolver: (_) async => [InternetAddress('8.8.8.8')],
        proxyResolver: (_) => 'DIRECT',
        clientFactory: () => _RealHttp().createHttpClient(null),
        connector: (_, _, hostname) => openSubscriptionTls(
          InternetAddress.loopbackIPv4,
          server.port,
          hostname,
          context: trusted,
        ),
      );
      final controller = AppController(
        subscriptionTransport: transport,
        clock: () => clock,
        jitter: (_) => 0,
      );
      var created = false;
      const sourceUri =
          'https://subscription.example.invalid/SYNTHETIC_HTTPS_PRIVATE';
      final sourceId = parseLink(sourceUri).localId;
      Future<void> settled() async {
        for (
          var attempt = 0;
          attempt < 200 &&
              (controller.refreshingSubscription ||
                  controller.storageState == ProfileStorageState.saving);
          attempt++
        ) {
          await tester.pump(const Duration(milliseconds: 100));
        }
        expect(controller.refreshingSubscription, isFalse);
        expect(controller.storageState, ProfileStorageState.saved);
      }

      try {
        await controller.initializeStorage();
        controller.import(sourceUri);
        created = true;
        await controller.refreshSubscription(sourceId);
        await settled();
        expect(controller.connections.length, 2);
        controller.select(
          controller.connections.singleWhere((item) => item.sourceId != null),
        );
        await settled();
        expect(
          controller.selected?.inspection?.status,
          NativeImportStatus.accepted,
        );
        expect(controller.stopPossible, isFalse);
        final cached = ProfileCache.decode((await storage.load()).payload!);
        expect(cached.subscriptions[sourceId]!.revision, 1);
        expect(
          cached.subscriptions[sourceId]!.lastAppliedAt == instant,
          isTrue,
        );
        await tester.pumpWidget(LiWeTunApp(controller: controller));
        await tester.tap(find.text('Серверы').last);
        await tester.pumpAndSettle();
        expect(find.text('Synthetic HTTPS subscription'), findsOneWidget);
        expect(find.text(sourceUri), findsNothing);
        clock = instant.add(const Duration(seconds: 6));
        revoked = true;
        await tester.tap(
          find.widgetWithText(OutlinedButton, 'Обновить подписку'),
        );
        await settled();
        await tester.pumpAndSettle();
        expect(controller.selected, isNull);
        expect(controller.connections.length, 1);
        expect(find.textContaining('Доступ отозван'), findsOneWidget);
        expect(controller.stopPossible, isFalse);
        expect(requests, 2);
        final denied = ProfileCache.decode((await storage.load()).payload!);
        expect(denied.subscriptions[sourceId]!.revision, 2);
        expect(denied.subscriptions[sourceId]!.access, Access.revoked);
      } finally {
        controller.dispose();
        await server.close(force: true);
        if (created) {
          final remaining = await storage.load();
          expect(remaining.code, StorageCode.ok);
          expect(
            (await storage.clear(remaining.revision)).code,
            StorageCode.ok,
          );
          expect((await storage.load()).code, StorageCode.missing);
        }
      }
    },
  );
  testWidgets(
    'actual tray capability keeps window reachable and persists opt-in',
    (tester) async {
      expect(Platform.environment['GITHUB_ACTIONS'], 'true');
      const storage = WindowsStorage();
      expect((await storage.load()).code, StorageCode.missing);
      final controller = AppController();
      var owned = false;
      var trayAvailable = false;
      try {
        await controller.initializeStorage();
        await controller.initializeDesktop();
        final initial = await WindowsDesktop.channel
            .invokeMapMethod<String, dynamic>('query');
        expect(initial?['available'], controller.desktopAvailable);
        expect(initial?['closeToTray'], false);
        expect(initial?['visible'], true);
        trayAvailable = controller.desktopAvailable;
        if (trayAvailable) {
          await controller.setCloseToTray(true);
          owned = true;
          for (
            var attempt = 0;
            attempt < 100 &&
                controller.storageState == ProfileStorageState.saving;
            attempt++
          ) {
            await tester.pump(const Duration(milliseconds: 50));
          }
          expect(controller.storageState, ProfileStorageState.saved);
          expect(
            ProfileCache.decode((await storage.load()).payload!).closeToTray,
            true,
          );
          final hidden = await WindowsDesktop.channel
              .invokeMapMethod<String, dynamic>('hide');
          expect(hidden?['visible'], false);
          expect(hidden?['closeToTray'], true);
          expect(controller.stopPossible, false);
          final shown = await WindowsDesktop.channel
              .invokeMapMethod<String, dynamic>('show');
          expect(shown?['visible'], true);
          await controller.setCloseToTray(false);
          for (
            var attempt = 0;
            attempt < 100 &&
                controller.storageState == ProfileStorageState.saving;
            attempt++
          ) {
            await tester.pump(const Duration(milliseconds: 50));
          }
          expect(
            ProfileCache.decode((await storage.load()).payload!).closeToTray,
            false,
          );
        } else {
          await controller.setCloseToTray(true);
          expect(controller.closeToTray, false);
          final untouched = await WindowsDesktop.channel
              .invokeMapMethod<String, dynamic>('hide');
          expect(untouched?['visible'], true);
          expect(untouched?['closeToTray'], false);
        }
      } finally {
        await WindowsDesktop.channel.invokeMethod<void>('show');
        await WindowsDesktop.channel.invokeMethod<void>('configure', {
          'closeToTray': false,
        });
        controller.dispose();
        if (owned) {
          final latest = await storage.load();
          expect((await storage.clear(latest.revision)).code, StorageCode.ok);
        }
        expect((await storage.load()).code, StorageCode.missing);
      }
      final workspace = Platform.environment['GITHUB_WORKSPACE']!;
      await File('$workspace/build/desktop-tray-evidence.json').writeAsString(
        jsonEncode({
          'source_commit': Platform.environment['GITHUB_SHA'],
          'passed': true,
          'available': trayAvailable,
          'hide_restore_tested': trayAvailable,
          'dpapi_tray_preference_tested': trayAvailable,
          'unavailable_visible_fallback_tested': !trayAvailable,
          'desktop_owner_acceptance': false,
          'tunnel_started': false,
        }),
      );
    },
  );
}
