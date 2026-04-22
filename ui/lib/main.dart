import 'dart:async';
import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'package:p43/src/rust/frb_generated.dart';
import 'package:path_provider/path_provider.dart';
import 'src/screens/agent_screen.dart';
import 'src/screens/devices_screen.dart';
import 'src/screens/key_list_screen.dart';
import 'src/screens/settings_screen.dart';
import 'src/services/notification_service.dart';
import 'src/services/settings_service.dart';
import 'src/services/telemetry_service.dart';
import 'src/services/window_service.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  final appDir = await getApplicationSupportDirectory();
  await setStoreDir(dir: appDir.path);
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

  // ── Unified Matrix listener ───────────────────────────────────────────────
  // A single mxListenAll subscription fans out to two broadcast controllers.
  // One sync loop = every message delivered exactly once.
  final StreamController<AgentRequest> _agentCtrl =
      StreamController<AgentRequest>.broadcast();
  final StreamController<BusCsrEvent> _busCtrl =
      StreamController<BusCsrEvent>.broadcast();
  final StreamController<void> _sessionLockCtrl =
      StreamController<void>.broadcast();
  StreamSubscription<AppMessage>? _allSub;

  @override
  void initState() {
    super.initState();
    _loggedIn = widget.initiallyLoggedIn;
    WidgetsBinding.instance.addObserver(this);
    _initListener();
  }

  @override
  void dispose() {
    _allSub?.cancel();
    _agentCtrl.close();
    _busCtrl.close();
    _sessionLockCtrl.close();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
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
          WindowService.instance.bringToFront();
        }
      },
      onError: (_) {},
      onDone: () {},
    );
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
    }
  }

  void _onLoggedIn() => setState(() => _loggedIn = true);
  void _onLoggedOut() => setState(() => _loggedIn = false);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
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
            onCsrRequest: () {
              if (_tabIndex != 2) setState(() => _tabIndex = 2);
            },
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
        onDestinationSelected: (i) => setState(() => _tabIndex = i),
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
