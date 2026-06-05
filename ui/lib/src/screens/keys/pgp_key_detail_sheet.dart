import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:p43/src/rust/api/simple.dart' as rust;
import 'key_export_sheet.dart';

/// Subkey / slot detail sheet — used for both `pgp-key` and `yubikey-ref`.
///
/// Shows: UID/label header + algo badge, subkeys/slots section, OpenSSH key
/// for the selected subkey, optional armored OpenPGP public key, and Remove.
class PgpKeyDetailSheet extends StatefulWidget {
  const PgpKeyDetailSheet({
    super.key,
    required this.walletMasterHex,
    required this.chainName,
    required this.kind,
    required this.onRemoved,
  });

  final String walletMasterHex;
  final String chainName;
  /// `"pgp-key"` or `"yubikey-ref"`.
  final String kind;
  final VoidCallback onRemoved;

  @override
  State<PgpKeyDetailSheet> createState() => _PgpKeyDetailSheetState();
}

class _PgpKeyDetailSheetState extends State<PgpKeyDetailSheet> {
  rust.WalletPgpKeyInfo? _info;
  String? _error;
  bool _removing = false;
  int _selectedSubkey = 0;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final info = widget.kind == 'yubikey-ref'
          ? await rust.walletGetYubikeyInfo(
              masterHex: widget.walletMasterHex,
              chainName: widget.chainName,
            )
          : await rust.walletGetPgpKeyInfo(
              masterHex: widget.walletMasterHex,
              chainName: widget.chainName,
            );
      if (!mounted) return;
      // Pre-select the first auth/sign subkey.
      final authIdx = info.subkeys.indexWhere(
          (s) => s.role.contains('auth') || s.role.contains('sign'));
      setState(() {
        _info = info;
        _selectedSubkey = authIdx >= 0 ? authIdx : 0;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = e.toString());
    }
  }

  Future<void> _confirmRemove() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text('Remove PGP key'),
        content: const Text(
          'This appends a tombstone to the chain.\n'
          'The key will no longer be accessible from the wallet.',
          style: TextStyle(fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: TextButton.styleFrom(
                foregroundColor: const Color(0xFFFF453A)),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    setState(() => _removing = true);
    try {
      await rust.walletRemoveEntry(
        masterHex: widget.walletMasterHex,
        chainName: widget.chainName,
      );
      widget.onRemoved();
      if (mounted) Navigator.pop(context);
    } catch (e) {
      if (mounted) setState(() { _removing = false; _error = e.toString(); });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.7,
      minChildSize: 0.4,
      maxChildSize: 0.95,
      builder: (_, ctrl) => Column(
        children: [
          // drag handle
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 10),
            child: Container(
              width: 36, height: 4,
              decoration: BoxDecoration(
                color: cs.onSurface.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),

          // ── header ─────────────────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 4, 12),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    _info?.uid ?? '…',
                    style: const TextStyle(
                        fontSize: 15, fontWeight: FontWeight.w600),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                if (_info != null) ...[
                  Text(
                    _info!.algo,
                    style: TextStyle(
                        fontSize: 12,
                        color: cs.onSurface.withValues(alpha: 0.5)),
                  ),
                  const SizedBox(width: 4),
                  // Export button
                  IconButton(
                    icon: const Icon(Icons.upload_outlined),
                    tooltip: 'Export public key',
                    onPressed: () => showModalBottomSheet<void>(
                      context: context,
                      isScrollControlled: true,
                      backgroundColor: const Color(0xFF1C1C1E),
                      shape: const RoundedRectangleBorder(
                        borderRadius:
                            BorderRadius.vertical(top: Radius.circular(16)),
                      ),
                      builder: (_) => WalletKeyExportSheet(
                        uid: _info!.uid,
                        pgpArmored: _info!.pubkeyArmored,
                        opensshKey: _info!.subkeys.isNotEmpty
                            ? _info!.subkeys[_selectedSubkey].opensshKey
                            : null,
                      ),
                    ),
                  ),
                ],
                _removing
                    ? const Padding(
                        padding: EdgeInsets.all(12),
                        child: SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2)),
                      )
                    : IconButton(
                        icon: const Icon(Icons.delete_outline,
                            color: Color(0xFFFF453A)),
                        tooltip: 'Remove from wallet',
                        onPressed: _confirmRemove,
                      ),
              ],
            ),
          ),
          const Divider(height: 1),

          // ── body ───────────────────────────────────────────────────────────
          Expanded(
            child: _error != null
                ? Center(
                    child: Padding(
                      padding: const EdgeInsets.all(24),
                      child: Text(_error!,
                          style:
                              const TextStyle(color: Color(0xFFFF453A))),
                    ),
                  )
                : _info == null
                    ? const Center(child: CircularProgressIndicator())
                    : ListView(
                        controller: ctrl,
                        padding: const EdgeInsets.all(16),
                        children: [
                          // ── subkeys ───────────────────────────────────────
                          if (_info!.subkeys.isNotEmpty) ...[
                            Padding(
                              padding: const EdgeInsets.only(bottom: 8),
                              child: Text(
                                'SUBKEYS',
                                style: TextStyle(
                                    fontSize: 11,
                                    fontWeight: FontWeight.w600,
                                    color:
                                        cs.onSurface.withValues(alpha: 0.5),
                                    letterSpacing: 0.5),
                              ),
                            ),
                            Container(
                              decoration: BoxDecoration(
                                color: const Color(0xFF1C1C1E),
                                borderRadius: BorderRadius.circular(10),
                                border:
                                    Border.all(color: const Color(0xFF3A3A3C)),
                              ),
                              child: Column(
                                children: [
                                  for (var i = 0;
                                      i < _info!.subkeys.length;
                                      i++) ...[
                                    if (i > 0)
                                      const Divider(
                                          height: 1,
                                          indent: 12,
                                          endIndent: 12),
                                    _SubkeyRow(
                                      subkey: _info!.subkeys[i],
                                      selected: i == _selectedSubkey,
                                      onTap: () =>
                                          setState(() => _selectedSubkey = i),
                                    ),
                                  ],
                                ],
                              ),
                            ),
                            const SizedBox(height: 20),
                          ],

                          // ── OpenSSH key for selected subkey ───────────────
                          if (_info!.subkeys.isNotEmpty &&
                              _info!.subkeys[_selectedSubkey].opensshKey !=
                                  null) ...[
                            _CopyableBlock(
                              label: 'OpenSSH (authorized_keys)',
                              value: _info!
                                  .subkeys[_selectedSubkey].opensshKey!,
                            ),
                            const SizedBox(height: 16),
                          ],

                          // ── Armored public key (hidden for YubiKey) ───────
                          if (_info!.pubkeyArmored.isNotEmpty)
                            _CopyableBlock(
                              label: 'OpenPGP Public Key',
                              value: _info!.pubkeyArmored,
                            ),
                        ],
                      ),
          ),
        ],
      ),
    );
  }
}

// ── Subkey row ────────────────────────────────────────────────────────────────

class _SubkeyRow extends StatelessWidget {
  final rust.SubkeyInfo subkey;
  final bool selected;
  final VoidCallback onTap;
  const _SubkeyRow(
      {required this.subkey, required this.selected, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final roles = subkey.role.toUpperCase().split('+');
    return InkWell(
      onTap: subkey.opensshKey != null ? onTap : null,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        child: Row(
          children: [
            // role badges
            Wrap(
              spacing: 4,
              children: roles
                  .map((r) => _RoleBadge(role: r))
                  .toList(),
            ),
            const Spacer(),
            Text(subkey.algo,
                style: const TextStyle(
                    fontSize: 12, color: Color(0xFF8E8E93))),
            if (subkey.opensshKey != null) ...[
              const SizedBox(width: 6),
              Icon(
                Icons.chevron_right,
                size: 16,
                color: selected
                    ? const Color(0xFF0A84FF)
                    : const Color(0xFF48484A),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _RoleBadge extends StatelessWidget {
  final String role;
  const _RoleBadge({required this.role});

  static const _colors = {
    'CERTIFY': (Color(0xFFFFCC00), Color(0xFF2A2200)),
    'SIGN': (Color(0xFFFFCC00), Color(0xFF2A2200)),
    'ENCRYPT': (Color(0xFF30D158), Color(0xFF0A2A12)),
    'AUTH': (Color(0xFF0A84FF), Color(0xFF0A1A2A)),
  };

  @override
  Widget build(BuildContext context) {
    final (fg, bg) =
        _colors[role] ?? (const Color(0xFF8E8E93), const Color(0xFF2C2C2E));
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
          color: bg, borderRadius: BorderRadius.circular(4)),
      child: Text(role,
          style: TextStyle(
              fontSize: 10, fontWeight: FontWeight.w700, color: fg)),
    );
  }
}

// ── Copyable block ────────────────────────────────────────────────────────────

class _CopyableBlock extends StatelessWidget {
  final String label;
  final String value;
  const _CopyableBlock({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(label,
                style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                    color: Color(0xFF8E8E93))),
            IconButton(
              iconSize: 18,
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(),
              icon: const Icon(Icons.copy_outlined, color: Color(0xFF0A84FF)),
              tooltip: 'Copy',
              onPressed: () {
                Clipboard.setData(ClipboardData(text: value));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                      content: Text('Copied'),
                      duration: Duration(seconds: 2)),
                );
              },
            ),
          ],
        ),
        const SizedBox(height: 4),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: const Color(0xFF1C1C1E),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: const Color(0xFF3A3A3C)),
          ),
          child: SelectableText(
            value,
            style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 11,
                color: Color(0xFFD1D1D6),
                height: 1.5),
          ),
        ),
      ],
    );
  }
}
