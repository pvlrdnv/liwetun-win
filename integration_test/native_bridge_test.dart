import 'package:flutter/services.dart';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:liwetun/app.dart';
import 'package:liwetun/app_controller.dart';
import 'package:liwetun/domain/import_link.dart';
import 'package:liwetun/native/trusttunnel.dart';
import 'package:liwetun/native/service.dart';
import 'package:liwetun/native/storage.dart';
import 'package:liwetun/domain/profile_cache.dart';
import 'package:liwetun/native/environment.dart';
import 'package:liwetun/diagnostics/journal.dart';

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
}
