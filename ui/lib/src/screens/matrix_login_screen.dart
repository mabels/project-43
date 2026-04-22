import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';

class MatrixLoginScreen extends StatefulWidget {
  const MatrixLoginScreen({super.key, required this.onLoggedIn});

  final VoidCallback onLoggedIn;

  @override
  State<MatrixLoginScreen> createState() => _MatrixLoginScreenState();
}

class _MatrixLoginScreenState extends State<MatrixLoginScreen> {
  final _homeserverCtrl = TextEditingController(text: 'https://matrix.org');
  final _usernameCtrl = TextEditingController();
  final _passwordCtrl = TextEditingController();
  bool _loading = false;
  String? _error;

  @override
  void dispose() {
    _homeserverCtrl.dispose();
    _usernameCtrl.dispose();
    _passwordCtrl.dispose();
    super.dispose();
  }

  Future<void> _login() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      await mxLogin(
        homeserver: _homeserverCtrl.text.trim(),
        username: _usernameCtrl.text.trim(),
        password: _passwordCtrl.text,
      );
      widget.onLoggedIn();
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF1C1C1E),
        title: const Text('Matrix Login'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const SizedBox(height: 16),
            _Field(
              controller: _homeserverCtrl,
              label: 'Homeserver',
              hint: 'https://matrix.org',
            ),
            const SizedBox(height: 12),
            _Field(
              controller: _usernameCtrl,
              label: 'Username',
              hint: '@alice:matrix.org',
            ),
            const SizedBox(height: 12),
            _Field(controller: _passwordCtrl, label: 'Password', obscure: true),
            if (_error != null) ...[
              const SizedBox(height: 12),
              Text(
                _error!,
                style: const TextStyle(color: Color(0xFFFF453A), fontSize: 13),
              ),
            ],
            const SizedBox(height: 24),
            FilledButton(
              onPressed: _loading ? null : _login,
              child: _loading
                  ? const SizedBox(
                      height: 18,
                      width: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Text('Login'),
            ),
            const SizedBox(height: 12),
            Text(
              'Your credentials are used only to authenticate with your homeserver '
              'and are never sent elsewhere.',
              style: TextStyle(
                fontSize: 11,
                color: cs.onSurface.withValues(alpha: 0.4),
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}

class _Field extends StatelessWidget {
  const _Field({
    required this.controller,
    required this.label,
    this.hint,
    this.obscure = false,
  });

  final TextEditingController controller;
  final String label;
  final String? hint;
  final bool obscure;

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: controller,
      obscureText: obscure,
      decoration: InputDecoration(
        labelText: label,
        hintText: hint,
        border: const OutlineInputBorder(),
      ),
    );
  }
}
