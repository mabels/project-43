import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'package:p43/src/rust/frb_generated.dart';
import 'package:path_provider/path_provider.dart';
import 'src/screens/agent_screen.dart';
import 'src/screens/key_list_screen.dart';
import 'src/screens/settings_screen.dart';
import 'src/services/notification_service.dart';
import 'src/services/settings_service.dart';
import 'src/services/window_service.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  final appDir = await getApplicationSupportDirectory();
  await setStoreDir(dir: appDir.path);
  // Load persisted settings before the UI starts.
  await SettingsService.instance.load();
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

  @override
  void initState() {
    super.initState();
    _loggedIn = widget.initiallyLoggedIn;
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
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
            onSignRequest: () {
              if (_tabIndex != 1) setState(() => _tabIndex = 1);
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
            icon: Icon(Icons.settings_outlined),
            selectedIcon: Icon(Icons.settings),
            label: 'Settings',
          ),
        ],
      ),
    );
  }
}
