import 'package:flutter/material.dart';
import '../../services/gate_key_service.dart';

/// Settings section for gate-key (wallet security) management.
///
/// Mirrors the CLI flow:
///   create      → first-time passphrase setup
///   add-passphrase → add another seal (proves ownership first)
///   add biometric  → store master in SE after unlocking
///   revoke      → remove a seal (requires a different working passphrase)
class GateKeySection extends StatefulWidget {
  const GateKeySection({super.key});

  @override
  State<GateKeySection> createState() => _GateKeySectionState();
}

class _GateKeySectionState extends State<GateKeySection> {
  final _svc = GateKeyService.instance;

  bool _configured = false;
  List<String> _seals = [];
  bool _hasBio = false;
  bool _bioAvailable = false;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final configured = await _svc.isConfigured();
    final seals = await _svc.listSeals();
    final hasBio = await _svc.hasBiometricSeal();
    final bioAvail = await _svc.biometricsAvailable;
    if (mounted) {
      setState(() {
        _configured = configured;
        _seals = seals;
        _hasBio = hasBio;
        _bioAvailable = bioAvail;
        _loading = false;
      });
    }
  }

  // ── Create (first-time setup) ──────────────────────────────────────────────

  Future<void> _create() async {
    final passphrase = await _promptPassphrase('Create master passphrase');
    if (passphrase == null || passphrase.isEmpty || !mounted) return;

    try {
      final result = await _svc.create(passphrase: passphrase);

      // Offer biometric if available.
      if (_bioAvailable && mounted) {
        final addBio = await _confirmDialog(
          'Also add Touch ID / Face ID?',
          'You can always add it later.',
        );
        if (addBio) {
          await _svc.addBiometricSeal(masterHex: result.masterHex);
        }
      }

      await _load();
      if (mounted) {
        _snack('Wallet security configured');
      }
    } catch (e) {
      if (mounted) _snack('Setup failed: $e', error: true);
    }
  }

  // ── Add passphrase ─────────────────────────────────────────────────────────

  Future<void> _addPassphrase() async {
    final existing = await _promptPassphrase('Existing passphrase (proves ownership)');
    if (existing == null || !mounted) return;

    String masterHex;
    try {
      masterHex = await _svc.unlockWithPassphrase(existing);
    } catch (_) {
      if (mounted) _snack('Wrong passphrase', error: true);
      return;
    }

    final newPass = await _promptPassphrase('New passphrase');
    if (newPass == null || newPass.isEmpty || !mounted) return;

    try {
      await _svc.addPassphraseSeal(masterHex: masterHex, newPassphrase: newPass);
      await _load();
      if (mounted) _snack('Passphrase seal added');
    } catch (e) {
      if (mounted) _snack('Failed: $e', error: true);
    }
  }

  // ── Add biometric ──────────────────────────────────────────────────────────

  Future<void> _addBiometric() async {
    final pass = await _promptPassphrase('Passphrase (to unlock master)');
    if (pass == null || !mounted) return;

    try {
      final masterHex = await _svc.unlockWithPassphrase(pass);
      await _svc.addBiometricSeal(masterHex: masterHex);
      await _load();
      if (mounted) _snack('Touch ID / Face ID added');
    } catch (e) {
      if (mounted) _snack('Failed: $e', error: true);
    }
  }

  // ── Revoke ─────────────────────────────────────────────────────────────────

  Future<void> _revoke(String keyId) async {
    if (_seals.length < 2 && !_hasBio) {
      _snack('Cannot revoke — only one seal remains', error: true);
      return;
    }
    final proof = await _promptPassphrase('Passphrase for a DIFFERENT seal (ownership proof)');
    if (proof == null || !mounted) return;

    try {
      await _svc.revokePassphraseSeal(keyId: keyId, proofPassphrase: proof);
      await _load();
      if (mounted) _snack('Seal $keyId revoked');
    } catch (e) {
      if (mounted) _snack('Failed: $e', error: true);
    }
  }

  Future<void> _removeBiometric() async {
    await _svc.removeBiometricSeal();
    await _load();
    if (mounted) _snack('Touch ID / Face ID removed');
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  Future<String?> _promptPassphrase(String label) async {
    final ctrl = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: Text(label, style: const TextStyle(fontSize: 15)),
        content: TextField(
          controller: ctrl,
          obscureText: true,
          autofocus: true,
          decoration: const InputDecoration(hintText: 'Passphrase'),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, ctrl.text), child: const Text('OK')),
        ],
      ),
    );
  }

  Future<bool> _confirmDialog(String title, String subtitle) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: Text(title, style: const TextStyle(fontSize: 15)),
        content: Text(subtitle,
            style: const TextStyle(fontSize: 13, color: Color(0xFF8E8E93))),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('No')),
          TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Yes')),
        ],
      ),
    );
    return result ?? false;
  }

  void _snack(String msg, {bool error = false}) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg),
      backgroundColor: error ? const Color(0xFFFF453A) : null,
    ));
  }

  // ── Build ──────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    if (_loading) return const SizedBox.shrink();

    if (!_configured) {
      return ListTile(
        tileColor: const Color(0xFF2C2C2E),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        leading: const Icon(Icons.lock_open, size: 20, color: Color(0xFFFF9F0A)),
        title: const Text('Wallet security', style: TextStyle(fontSize: 15)),
        subtitle: const Text('Not configured',
            style: TextStyle(fontSize: 12, color: Color(0xFFFF9F0A))),
        trailing: TextButton(onPressed: _create, child: const Text('Set up')),
      );
    }

    // Configured — show seals and management options.
    final sealCount = _seals.length;
    final subtitle = [
      '$sealCount passphrase seal${sealCount != 1 ? 's' : ''}',
      if (_hasBio) 'Touch ID / Face ID',
    ].join(' · ');

    return ExpansionTile(
      backgroundColor: const Color(0xFF2C2C2E),
      collapsedBackgroundColor: const Color(0xFF2C2C2E),
      leading: const Icon(Icons.lock, size: 20, color: Color(0xFF30D158)),
      title: const Text('Wallet security', style: TextStyle(fontSize: 15)),
      subtitle: Text(subtitle,
          style: const TextStyle(fontSize: 12, color: Color(0xFF30D158))),
      children: [
        // Passphrase seals
        for (final id in _seals)
          ListTile(
            dense: true,
            tileColor: const Color(0xFF1C1C1E),
            contentPadding: const EdgeInsets.symmetric(horizontal: 24, vertical: 0),
            leading: const Icon(Icons.vpn_key_outlined, size: 16,
                color: Color(0xFF8E8E93)),
            title: Text(id,
                style: const TextStyle(fontSize: 13, fontFamily: 'monospace')),
            trailing: _seals.length > 1 || _hasBio
                ? IconButton(
                    icon: const Icon(Icons.delete_outline, size: 16,
                        color: Color(0xFFFF453A)),
                    onPressed: () => _revoke(id),
                  )
                : null,
          ),
        // Biometric seal
        if (_hasBio)
          ListTile(
            dense: true,
            tileColor: const Color(0xFF1C1C1E),
            contentPadding: const EdgeInsets.symmetric(horizontal: 24, vertical: 0),
            leading: const Icon(Icons.fingerprint, size: 16, color: Color(0xFF8E8E93)),
            title: const Text('Touch ID / Face ID',
                style: TextStyle(fontSize: 13)),
            trailing: IconButton(
              icon: const Icon(Icons.delete_outline, size: 16,
                  color: Color(0xFFFF453A)),
              onPressed: _removeBiometric,
            ),
          ),
        // Action buttons
        Padding(
          padding: const EdgeInsets.fromLTRB(24, 4, 24, 8),
          child: Wrap(
            spacing: 8,
            children: [
              OutlinedButton.icon(
                onPressed: _addPassphrase,
                icon: const Icon(Icons.add, size: 14),
                label: const Text('Add passphrase', style: TextStyle(fontSize: 12)),
              ),
              if (_bioAvailable && !_hasBio)
                OutlinedButton.icon(
                  onPressed: _addBiometric,
                  icon: const Icon(Icons.fingerprint, size: 14),
                  label: const Text('Add Touch ID', style: TextStyle(fontSize: 12)),
                ),
            ],
          ),
        ),
      ],
    );
  }
}
