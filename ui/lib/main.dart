import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'package:p43/src/rust/frb_generated.dart';
import 'package:path_provider/path_provider.dart';
import 'src/screens/agent_screen.dart';
import 'src/screens/key_list_screen.dart';
import 'src/screens/matrix_login_screen.dart';
import 'src/screens/matrix_room_list_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  final appDir = await getApplicationSupportDirectory();
  await setStoreDir(dir: appDir.path);
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

class _RootShellState extends State<_RootShell> {
  int _tabIndex = 0;
  late bool _loggedIn;

  @override
  void initState() {
    super.initState();
    _loggedIn = widget.initiallyLoggedIn;
  }

  void _onLoggedIn() => setState(() => _loggedIn = true);
  void _onLoggedOut() => setState(() => _loggedIn = false);

  @override
  Widget build(BuildContext context) {
    final chatScreen = _loggedIn
        ? MatrixRoomListScreen(onLoggedOut: _onLoggedOut)
        : MatrixLoginScreen(onLoggedIn: _onLoggedIn);

    return Scaffold(
      body: IndexedStack(
        index: _tabIndex,
        children: [
          const KeyListScreen(),
          chatScreen,
          const AgentScreen(),
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
            icon: Icon(Icons.chat_bubble_outline),
            selectedIcon: Icon(Icons.chat_bubble),
            label: 'Chat',
          ),
          NavigationDestination(
            icon: Icon(Icons.terminal_outlined),
            selectedIcon: Icon(Icons.terminal),
            label: 'Agent',
          ),
        ],
      ),
    );
  }
}
