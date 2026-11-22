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
  List<rust.WalletEntry>? _entries;
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
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      // Use the wallet list (full with ids & labels, in saved order) via bridge
      final result = await rust.walletListWithIds(
        masterHex: widget.walletMasterHex!,
      );
      if (mounted) {
        setState(() {
          _entries = List<rust.WalletEntry>.from(result);
          _loading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _loading = false;
        });
      }
    }
  }

  Future<void> _onReorderItem(int oldIndex, int newIndex) async {
    final entries = _entries;
    if (entries == null || widget.walletMasterHex == null) return;
    if (oldIndex == newIndex) return;

    final previous = List<rust.WalletEntry>.from(entries);
    setState(() {
      final item = entries.removeAt(oldIndex);
      entries.insert(newIndex, item);
    });

    try {
      await rust.walletSetKeyOrder(
        masterHex: widget.walletMasterHex!,
        order: entries.map((e) => e.chainName).toList(),
      );
    } catch (e) {
      if (!mounted) return;
      setState(() => _entries = previous);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to save key order: $e')),
      );
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
            const Text(
              'Wallet locked',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
            ),
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
      final isDecryptError =
          _error!.contains('decryption failed') ||
          _error!.contains('wrong key') ||
          _error!.contains('corrupted');
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(
                Icons.error_outline,
                size: 48,
                color: Color(0xFFFF453A),
              ),
              const SizedBox(height: 12),
              Text(
                isDecryptError
                    ? 'Stale data detected'
                    : 'Failed to load credentials',
                style: const TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w500,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                isDecryptError
                    ? 'Some stored entries were encrypted with an old key.\n'
                          'Delete the sync-store data and re-add your credentials.'
                    : _error!,
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
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
            Icon(Icons.lock_open_outlined, size: 48, color: Color(0xFF48484A)),
            SizedBox(height: 12),
            Text(
              'No credentials yet.',
              style: TextStyle(fontSize: 15, fontWeight: FontWeight.w500),
            ),
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

    // Compute 1-based SSH agent order for SSH-emitted entries (ssh-key, yubikey-ref).
    final sshOrderByChain = <String, int>{};
    var sshRank = 0;
    for (final e in entries) {
      if (e.kind == 'ssh-key' || e.kind == 'yubikey-ref') {
        sshRank += 1;
        sshOrderByChain[e.chainName] = sshRank;
      }
    }

    return ReorderableListView.builder(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      buildDefaultDragHandles: false,
      onReorderItem: _onReorderItem,
      proxyDecorator: (child, index, animation) => Material(
        color: Colors.transparent,
        elevation: 6,
        shadowColor: Colors.black54,
        borderRadius: BorderRadius.circular(12),
        child: child,
      ),
      itemCount: entries.length,
      itemBuilder: (context, i) {
        final entry = entries[i];
        final name = entry.chainName;
        final kind = entry.kind;
        // fingerprint = everything before the last -kind suffix
        final fp = name.endsWith('-$kind')
            ? name.substring(0, name.length - kind.length - 1)
            : name;
        return Padding(
          key: ValueKey(name),
          padding: EdgeInsets.only(bottom: i < entries.length - 1 ? 8 : 0),
          child: _CredentialCard(
            index: i,
            chainName: name,
            kind: kind,
            fingerprint: fp,
            label: entry.label,
            sshOrder: sshOrderByChain[name],
            onTap: () {
              showModalBottomSheet(
                context: context,
                isScrollControlled: true,
                backgroundColor: const Color(0xFF2C2C2E),
                shape: const RoundedRectangleBorder(
                  borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
                ),
                builder: (_) => (kind == 'pgp-key' || kind == 'yubikey-ref')
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
          ),
        );
      },
    );
  }
}

// ── Credential card — mirrors KeyCard visual style ────────────────────────────

class _CredentialCard extends StatelessWidget {
  final int index;
  final String chainName;
  final String kind;
  final String fingerprint;
  final String label;
  final int? sshOrder;
  final VoidCallback onTap;

  const _CredentialCard({
    required this.index,
    required this.chainName,
    required this.kind,
    required this.fingerprint,
    required this.label,
    required this.sshOrder,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final (badgeLabel, badgeColor, badgeBg) = switch (kind) {
      'yubikey-ref' => (
        'yubikey',
        const Color(0xFF30D158), // green — hardware
        const Color(0xFF0A2A12),
      ),
      'pgp-key' => (
        'pgp',
        const Color(0xFFFF9F0A), // orange — crypto key
        const Color(0xFF2A1A00),
      ),
      'authority-key' => (
        'authority',
        const Color(0xFFBF5AF2), // purple — bus authority
        const Color(0xFF1A0A2A),
      ),
      'device-id' || 'certified-device-id' => (
        'device',
        const Color(0xFF8E8E93), // gray — bus device identity
        const Color(0xFF1C1C1E),
      ),
      _ => (
        'ssh',
        const Color(0xFF0A84FF), // blue — software
        const Color(0xFF0A1A2A),
      ),
    };

    final displayTitle = label.isNotEmpty ? label : fingerprint;

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Container(
        padding: const EdgeInsets.fromLTRB(6, 12, 14, 12),
        decoration: BoxDecoration(
          color: const Color(0xFF2C2C2E),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: const Color(0xFF3A3A3C)),
        ),
        child: Row(
          children: [
            // ── drag handle ──
            ReorderableDragStartListener(
              index: index,
              child: const MouseRegion(
                cursor: SystemMouseCursors.grab,
                child: Padding(
                  padding: EdgeInsets.symmetric(horizontal: 6, vertical: 4),
                  child: Icon(
                    Icons.drag_handle,
                    size: 18,
                    color: Color(0xFF636366),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 4),
            // ── card body ──
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // ── top row: title + ssh order + badge + chevron ──
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          displayTitle,
                          style: const TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      if (sshOrder != null) ...[
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 5,
                            vertical: 2,
                          ),
                          decoration: BoxDecoration(
                            color: const Color(0xFF1C1C1E),
                            borderRadius: BorderRadius.circular(4),
                            border: Border.all(color: const Color(0xFF3A3A3C)),
                          ),
                          child: Text(
                            '#$sshOrder',
                            style: const TextStyle(
                              fontSize: 10,
                              fontWeight: FontWeight.w600,
                              fontFamily: 'monospace',
                              color: Color(0xFFAEAEB2),
                            ),
                          ),
                        ),
                      ],
                      const SizedBox(width: 6),
                      // kind badge
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 6,
                          vertical: 2,
                        ),
                        decoration: BoxDecoration(
                          color: badgeBg,
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          badgeLabel,
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.w700,
                            color: badgeColor,
                          ),
                        ),
                      ),
                      const SizedBox(width: 6),
                      const Icon(
                        Icons.chevron_right,
                        size: 16,
                        color: Color(0xFF48484A),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  // ── bottom row: icon + kind label (+ fingerprint if label differs) ──
                  Row(
                    children: [
                      Icon(
                        switch (kind) {
                          'yubikey-ref' => Icons.credit_card_outlined,
                          'pgp-key' => Icons.lock_outlined,
                          'authority-key' => Icons.verified_user_outlined,
                          'device-id' || 'certified-device-id' =>
                            Icons.devices_outlined,
                          _ => Icons.key_outlined,
                        },
                        size: 13,
                        color: const Color(0xFF8E8E93),
                      ),
                      const SizedBox(width: 5),
                      Expanded(
                        child: Text(
                          switch (kind) {
                            'yubikey-ref' =>
                              label.isNotEmpty
                                  ? 'YubiKey · $fingerprint'
                                  : 'YubiKey reference',
                            'pgp-key' => 'OpenPGP key',
                            'authority-key' => 'Bus authority',
                            'device-id' || 'certified-device-id' =>
                              'Device · $fingerprint',
                            _ =>
                              label.isNotEmpty
                                  ? 'SSH key · $fingerprint'
                                  : 'SSH key',
                          },
                          style: const TextStyle(
                            fontSize: 11,
                            color: Color(0xFF8E8E93),
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
