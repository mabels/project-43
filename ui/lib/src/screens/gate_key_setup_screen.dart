import 'package:flutter/material.dart';
import '../services/gate_key_service.dart';

/// Full-screen setup flow shown on first launch when no gate-key exists.
///
/// Cannot be dismissed — the user must complete setup before using the app.
class GateKeySetupScreen extends StatefulWidget {
  /// Called after successful setup so the caller can navigate to the main shell.
  final VoidCallback onSetupComplete;

  const GateKeySetupScreen({super.key, required this.onSetupComplete});

  @override
  State<GateKeySetupScreen> createState() => _GateKeySetupScreenState();
}

class _GateKeySetupScreenState extends State<GateKeySetupScreen> {
  final _svc = GateKeyService.instance;
  final _passCtrl = TextEditingController();
  final _confirmCtrl = TextEditingController();
  bool _busy = false;
  bool _bioAvailable = false;
  bool _addBio = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _checkBio();
  }

  Future<void> _checkBio() async {
    final bio = await _svc.biometricsAvailable;
    if (mounted) setState(() => _bioAvailable = bio);
  }

  Future<void> _setup() async {
    final pass = _passCtrl.text.trim();
    final confirm = _confirmCtrl.text.trim();

    if (pass.isEmpty) {
      setState(() => _error = 'Passphrase is required');
      return;
    }
    if (pass != confirm) {
      setState(() => _error = 'Passphrases do not match');
      return;
    }

    setState(() { _busy = true; _error = null; });

    try {
      final result = await _svc.create(passphrase: pass);

      if (_addBio && _bioAvailable) {
        await _svc.addBiometricSeal(masterHex: result.masterHex);
      }

      widget.onSetupComplete();
    } catch (e) {
      if (mounted) setState(() { _busy = false; _error = e.toString(); });
    }
  }

  @override
  void dispose() {
    _passCtrl.dispose();
    _confirmCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF1C1C1E),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Icon(Icons.lock_outline, size: 56, color: Color(0xFF0A84FF)),
                const SizedBox(height: 24),
                const Text(
                  'Secure your wallet',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 22, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 8),
                const Text(
                  'Create a master passphrase to protect your credentials.\n'
                  'You can add Touch ID or additional passphrases later.',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 14, color: Color(0xFF8E8E93)),
                ),
                const SizedBox(height: 32),

                // Passphrase
                TextField(
                  controller: _passCtrl,
                  obscureText: true,
                  decoration: const InputDecoration(
                    labelText: 'Master passphrase',
                    filled: true,
                    fillColor: Color(0xFF2C2C2E),
                    border: OutlineInputBorder(),
                  ),
                ),
                const SizedBox(height: 12),

                // Confirm
                TextField(
                  controller: _confirmCtrl,
                  obscureText: true,
                  decoration: const InputDecoration(
                    labelText: 'Confirm passphrase',
                    filled: true,
                    fillColor: Color(0xFF2C2C2E),
                    border: OutlineInputBorder(),
                  ),
                  onSubmitted: (_) => _setup(),
                ),

                // Biometric option
                if (_bioAvailable) ...[
                  const SizedBox(height: 16),
                  SwitchListTile(
                    tileColor: const Color(0xFF2C2C2E),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                    title: const Text('Also enable Touch ID / Face ID',
                        style: TextStyle(fontSize: 14)),
                    subtitle: const Text('Unlock without typing the passphrase',
                        style: TextStyle(fontSize: 12, color: Color(0xFF8E8E93))),
                    value: _addBio,
                    onChanged: (v) => setState(() => _addBio = v),
                  ),
                ],

                // Error
                if (_error != null) ...[
                  const SizedBox(height: 12),
                  Text(_error!,
                      style: const TextStyle(
                          color: Color(0xFFFF453A), fontSize: 13)),
                ],

                const SizedBox(height: 24),

                // Submit
                FilledButton(
                  onPressed: _busy ? null : _setup,
                  child: _busy
                      ? const SizedBox(
                          height: 18,
                          width: 18,
                          child: CircularProgressIndicator(
                              strokeWidth: 2, color: Colors.white),
                        )
                      : const Text('Set up wallet'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
