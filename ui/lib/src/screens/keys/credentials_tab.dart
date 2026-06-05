import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart' as rust;
import 'credential_detail_sheet.dart';
import 'pgp_key_detail_sheet.dart';

/// The Credentials tab on the Keys page.
///
/// Shows wallet entries (yubikey-ref, ssh-key) when the wallet is unlocked.
/// If locked, shows an unlock prompt.
class CredentialsTab extends StatefulWidget {
  /// Non-null = wallet is unlocked; the value is the master hex.
  final String? walletMasterHex;

  const CredentialsTab({super.key, required this.walletMasterHex});

  @override
  State<CredentialsTab> createState() => _CredentialsTabState();
}

class _CredentialsTabState extends State<CredentialsTab> {
  List<(String, String)>? _entries; // (chain_name, kind)
  bool _loading = false;
  String? _error;

  @override
  void didUpdateWidget(CredentialsTab old) {
    super.didUpdateWidget(old);
    if (widget.walletMasterHex != old.walletMasterHex &&
        widget.walletMasterHex != null) {
      _load();
    }
  }

  @override
  void initState() {
    super.initState();
    if (widget.walletMasterHex != null) _load();
  }

  Future<void> _load() async {
    if (widget.walletMasterHex == null) return;
    setState(() { _loading = true; _error = null; });
    try {
      // Use the wallet list (full with ids) via bridge
      final result = await rust.walletListWithIds(
        masterHex: widget.walletMasterHex!,
      );
      if (mounted) {
        setState(() {
          _entries = result.map((e) => (e.chainName, e.kind)).toList();
          _loading = false;
        });
      }
    } catch (e) {
      if (mounted) setState(() { _error = e.toString(); _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (widget.walletMasterHex == null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.lock_outline, size: 48, color: Color(0xFF8E8E93)),
            const SizedBox(height: 12),
            const Text('Wallet locked',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500)),
            const SizedBox(height: 6),
            const Text(
              'Tap the lock icon to unlock.',
              style: TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
            ),
          ],
        ),
      );
    }

    if (_loading) return const Center(child: CircularProgressIndicator());

    if (_error != null) {
      final isDecryptError = _error!.contains('decryption failed') ||
          _error!.contains('wrong key') ||
          _error!.contains('corrupted');
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.error_outline,
                  size: 48, color: Color(0xFFFF453A)),
              const SizedBox(height: 12),
              Text(
                isDecryptError
                    ? 'Stale data detected'
                    : 'Failed to load credentials',
                style: const TextStyle(
                    fontSize: 16, fontWeight: FontWeight.w500),
              ),
              const SizedBox(height: 8),
              Text(
                isDecryptError
                    ? 'Some stored entries were encrypted with an old key.\n'
                        'Delete the sync-store data and re-add your credentials.'
                    : _error!,
                textAlign: TextAlign.center,
                style: const TextStyle(
                    fontSize: 13, color: Color(0xFF8E8E93)),
              ),
            ],
          ),
        ),
      );
    }

    final entries = _entries ?? [];
    if (entries.isEmpty) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.lock_open_outlined,
                size: 48, color: Color(0xFF48484A)),
            SizedBox(height: 12),
            Text('No credentials yet.',
                style: TextStyle(
                    fontSize: 15, fontWeight: FontWeight.w500)),
            SizedBox(height: 6),
            Text(
              'Use the card or key buttons above to add.',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
            ),
          ],
        ),
      );
    }

    return ListView.separated(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      itemCount: entries.length,
      separatorBuilder: (ctx, idx) => const SizedBox(height: 8),
      itemBuilder: (context, i) {
        final (name, kind) = entries[i];
        // fingerprint = everything before the last -kind suffix
        final fp = name.endsWith('-$kind')
            ? name.substring(0, name.length - kind.length - 1)
            : name;
        return _CredentialCard(
          chainName: name,
          kind: kind,
          fingerprint: fp,
          onTap: () {
            showModalBottomSheet(
              context: context,
              isScrollControlled: true,
              backgroundColor: const Color(0xFF2C2C2E),
              shape: const RoundedRectangleBorder(
                borderRadius:
                    BorderRadius.vertical(top: Radius.circular(16)),
              ),
              builder: (_) =>
                  (kind == 'pgp-key' || kind == 'yubikey-ref')
                  ? PgpKeyDetailSheet(
                      walletMasterHex: widget.walletMasterHex!,
                      chainName: name,
                      kind: kind,
                      onRemoved: _load,
                    )
                  : CredentialDetailSheet(
                      walletMasterHex: widget.walletMasterHex!,
                      chainName: name,
                      kind: kind,
                      onRemoved: _load,
                    ),
            );
          },
        );
      },
    );
  }
}

// ── Credential card — mirrors KeyCard visual style ────────────────────────────

class _CredentialCard extends StatelessWidget {
  final String chainName;
  final String kind;
  final String fingerprint;
  final VoidCallback onTap;

  const _CredentialCard({
    required this.chainName,
    required this.kind,
    required this.fingerprint,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final (badgeLabel, badgeColor, badgeBg) = switch (kind) {
      'yubikey-ref' => (
          'yubikey',
          const Color(0xFF30D158),  // green — hardware
          const Color(0xFF0A2A12),
        ),
      'pgp-key' => (
          'pgp',
          const Color(0xFFFF9F0A),  // orange — crypto key
          const Color(0xFF2A1A00),
        ),
      'authority-key' => (
          'authority',
          const Color(0xFFBF5AF2),  // purple — bus authority
          const Color(0xFF1A0A2A),
        ),
      _ => (
          'ssh',
          const Color(0xFF0A84FF),  // blue — software
          const Color(0xFF0A1A2A),
        ),
    };

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        decoration: BoxDecoration(
          color: const Color(0xFF2C2C2E),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: const Color(0xFF3A3A3C)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── top row: fingerprint + badge + chevron ──
            Row(
              children: [
                Expanded(
                  child: Text(
                    fingerprint,
                    style: const TextStyle(
                        fontSize: 14, fontWeight: FontWeight.w600),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                const SizedBox(width: 8),
                // kind badge
                Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: badgeBg,
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    badgeLabel,
                    style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        color: badgeColor),
                  ),
                ),
                const SizedBox(width: 6),
                const Icon(Icons.chevron_right,
                    size: 16, color: Color(0xFF48484A)),
              ],
            ),
            const SizedBox(height: 6),
            // ── bottom row: icon + kind label ──
            Row(
              children: [
                Icon(
                  switch (kind) {
                    'yubikey-ref' => Icons.credit_card_outlined,
                    'pgp-key' => Icons.lock_outlined,
                    'authority-key' => Icons.verified_user_outlined,
                    _ => Icons.key_outlined,
                  },
                  size: 13,
                  color: const Color(0xFF8E8E93),
                ),
                const SizedBox(width: 5),
                Text(
                  switch (kind) {
                    'yubikey-ref' => 'YubiKey reference',
                    'pgp-key' => 'OpenPGP key',
                    'authority-key' => 'Bus authority',
                    _ => 'SSH key',
                  },
                  style: const TextStyle(
                      fontSize: 11, color: Color(0xFF8E8E93)),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
