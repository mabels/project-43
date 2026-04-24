import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'package:p43/src/rust/frb_generated.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'src/screens/agent_screen.dart';
import 'src/screens/devices_screen.dart';
import 'src/screens/key_list_screen.dart';
import 'src/screens/settings_screen.dart';
import 'src/services/notification_service.dart';
import 'src/services/settings_service.dart';
import 'src/services/telemetry_service.dart';
import 'src/services/window_service.dart';

/// Resolve the store root directory.
///
/// On macOS and Linux the CLI uses `~/.config/project-43/`, so the desktop
/// app uses the same path so that both share keys, Matrix session, and bus
/// data without duplication or bundle-ID-sensitive paths.
///
/// On iOS and Android `getApplicationSupportDirectory()` is the right choice
/// because there is no shared CLI.
Future<String> _resolveStoreDir() async {
  if (Platform.isMacOS || Platform.isLinux) {
    final home = Platform.environment['HOME'];
    if (home != null && home.isNotEmpty) {
      return p.join(home, '.config', 'project-43');
    }
  }
  final appDir = await getApplicationSupportDirectory();
  return appDir.path;
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  final storeDir = await _resolveStoreDir();
  await setStoreDir(dir: storeDir);
  // Load persisted settings before the UI starts.
  await SettingsService.instance.load();
  // Initialise telemetry using the persisted endpoint.
  // Empty string → local/no-op mode (no network).  Non-empty → OTLP export.
  await TelemetryService.instance.init(
    endpoint: SettingsService.instance.settings.otelEndpoint,
  );
  // Initialise notification service (requests OS permission on first run).
  await NotificationService.instance.init();
  // Initialise window management (desktop only — no-op on mobile).
  await WindowService.instance.init();
  // Attempt to restore a previously saved Matrix session.
  final loggedIn = await mxRestore();
  runApp(P43App(initiallyLoggedIn: loggedIn));
}

class P43App extends StatelessWidget {
  const P43App({super.key, required this.initiallyLoggedIn});

  final bool initiallyLoggedIn;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'p43',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF0A84FF),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFF1C1C1E),
        cardColor: const Color(0xFF2C2C2E),
        dividerColor: const Color(0xFF3A3A3C),
        fontFamily: '.AppleSystemUIFont',
      ),
      home: _RootShell(initiallyLoggedIn: initiallyLoggedIn),
    );
  }
}

class _RootShell extends StatefulWidget {
  const _RootShell({required this.initiallyLoggedIn});

  final bool initiallyLoggedIn;

  @override
  State<_RootShell> createState() => _RootShellState();
}

class _RootShellState extends State<_RootShell> with WidgetsBindingObserver {
  int _tabIndex = 0;
  late bool _loggedIn;
  bool _sessionUnlocked = false;

  static const _tabTitles = ['Keys', 'Agent', 'Devices', 'Settings'];

  // ── Unified Matrix listener ───────────────────────────────────────────────
  // A single mxListenAll subscription fans out to two broadcast controllers.
  // One sync loop = every message delivered exactly once.
  final StreamController<AgentRequest> _agentCtrl =
      StreamController<AgentRequest>.broadcast();
  final StreamController<BusCsrEvent> _busCtrl =
      StreamController<BusCsrEvent>.broadcast();
  final StreamController<void> _sessionLockCtrl =
      StreamController<void>.broadcast();

  /// Emitted when the user taps the AppBar lock icon while locked.
  /// Consumed by [DevicesScreen] to navigate to the Authority sub-tab and open
  /// the unlock dialog without showing an OS notification.
  final StreamController<void> _unlockRequestCtrl =
      StreamController<void>.broadcast();

  /// Emitted whenever the session is locked (AppBar button or lifecycle event).
  /// Forwarded to [SessionUnlockTile] so its visual stays in sync.
  final StreamController<void> _externalLockCtrl =
      StreamController<void>.broadcast();
  StreamSubscription<AppMessage>? _allSub;

  @override
  void initState() {
    super.initState();
    _loggedIn = widget.initiallyLoggedIn;
    WidgetsBinding.instance.addObserver(this);
    _initListener();
    _refreshLockState();
  }

  @override
  void dispose() {
    _allSub?.cancel();
    _agentCtrl.close();
    _busCtrl.close();
    _sessionLockCtrl.close();
    _unlockRequestCtrl.close();
    _externalLockCtrl.close();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  Future<void> _refreshLockState() async {
    try {
      final v = await busIsSessionUnlocked();
      if (mounted) setState(() => _sessionUnlocked = v);
    } catch (_) {}
  }

  void _lockAll() {
    lockAll();
    SettingsService.instance.invalidateCache();
    _externalLockCtrl.add(null);
    setState(() => _sessionUnlocked = false);
  }

  /// Switches to the Devices tab and emits on [_unlockRequestCtrl] so
  /// [DevicesScreen] can animate to the Authority sub-tab and open the dialog.
  void _openUnlockDialog() {
    if (_tabIndex != 2) setState(() => _tabIndex = 2);
    _unlockRequestCtrl.add(null);
  }

  Future<void> _initListener() async {
    try {
      final room = await mxGetAgentRoom();
      if (room != null) _startAllListening(room);
    } catch (_) {}
  }

  void _startAllListening(String roomId) {
    _allSub?.cancel();
    _allSub = mxListenAll(roomId: roomId).listen(
      (msg) {
        if (msg is AppMessage_AgentEvent) {
          _agentCtrl.add(msg.event);
        } else if (msg is AppMessage_BusEvent) {
          _busCtrl.add(msg.event);
        } else if (msg is AppMessage_SessionLockRequired) {
          if (_tabIndex != 2) setState(() => _tabIndex = 2);
          _sessionLockCtrl.add(null);
          _externalLockCtrl.add(null);
          WindowService.instance.bringToFront();
          // A BusSecure message arrived that we couldn't decrypt — reflect
          // the locked state in the global lock icon immediately.
          if (mounted) setState(() => _sessionUnlocked = false);
        }
      },
      onError: (_) => _scheduleReconnect(roomId),
      onDone: () => _scheduleReconnect(roomId),
    );
  }

  /// Reconnects the Matrix listener after a short delay.
  ///
  /// Called from both [onDone] (server closed the sync connection — normal
  /// after a long idle) and [onError] (network blip).  The 5 s delay avoids
  /// tight retry loops when the server is transiently unavailable.
  void _scheduleReconnect(String roomId) {
    Future.delayed(const Duration(seconds: 5), () {
      if (mounted) _startAllListening(roomId);
    });
  }

  /// Called by [AgentScreen] when the user selects a different agent room.
  void _onAgentRoomChanged(String roomId) {
    _startAllListening(roomId);
  }

  /// Clear credential caches when the screen locks or the app goes to the
  /// background.  On mobile [paused] fires on screen-lock; on macOS/desktop
  /// [hidden] fires when the window is hidden (including screen-saver lock).
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden) {
      SettingsService.instance.invalidateCache();
      _externalLockCtrl.add(null);
      if (mounted) setState(() => _sessionUnlocked = false);
    } else if (state == AppLifecycleState.resumed) {
      _refreshLockState();
    }
  }

  void _onLoggedIn() => setState(() => _loggedIn = true);
  void _onLoggedOut() => setState(() => _loggedIn = false);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF1C1C1E),
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
        title: Text(
          _tabTitles[_tabIndex],
          style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w600),
        ),
        actions: [
          IconButton(
            tooltip: _sessionUnlocked ? 'Lock session' : 'Unlock session',
            icon: Icon(
              _sessionUnlocked ? Icons.lock_open_outlined : Icons.lock_outlined,
            ),
            color: _sessionUnlocked
                ? const Color(0xFFFF9F0A) // amber — something to lock
                : Colors.grey,
            onPressed: _sessionUnlocked ? _lockAll : _openUnlockDialog,
          ),
          const SizedBox(width: 4),
        ],
      ),
      body: IndexedStack(
        index: _tabIndex,
        children: [
          const KeyListScreen(),
          AgentScreen(
            agentStream: _agentCtrl.stream,
            onSignRequest: () {
              if (_tabIndex != 1) setState(() => _tabIndex = 1);
            },
            onRoomChanged: _onAgentRoomChanged,
          ),
          DevicesScreen(
            busStream: _busCtrl.stream,
            sessionLockStream: _sessionLockCtrl.stream,
            unlockRequestStream: _unlockRequestCtrl.stream,
            externalLockStream: _externalLockCtrl.stream,
            onCsrRequest: () {
              if (_tabIndex != 2) setState(() => _tabIndex = 2);
            },
            onSessionUnlocked: _refreshLockState,
          ),
          SettingsScreen(
            loggedIn: _loggedIn,
            onLoggedIn: _onLoggedIn,
            onLoggedOut: _onLoggedOut,
          ),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        backgroundColor: const Color(0xFF1C1C1E),
        selectedIndex: _tabIndex,
        onDestinationSelected: (i) {
          setState(() => _tabIndex = i);
          // Refresh lock icon when navigating — the user may have just
          // unlocked the session from the Devices tab.
          _refreshLockState();
        },
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.key_outlined),
            selectedIcon: Icon(Icons.key),
            label: 'Keys',
          ),
          NavigationDestination(
            icon: Icon(Icons.terminal_outlined),
            selectedIcon: Icon(Icons.terminal),
            label: 'Agent',
          ),
          NavigationDestination(
            icon: Icon(Icons.devices_outlined),
            selectedIcon: Icon(Icons.devices),
            label: 'Devices',
          ),
          NavigationDestination(
            icon: Icon(Icons.settings_outlined),
            selectedIcon: Icon(Icons.settings),
            label: 'Settings',
          ),
        ],
      ),
    );
  }
}
