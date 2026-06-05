import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:p43/src/rust/api/simple.dart' as rust;

/// Detail sheet for YubiKey reference and SSH key wallet entries.
///
/// Matches the PgpKeyDetailSheet layout: DraggableScrollableSheet, header bar
/// with label + badge + delete button, then content with copyable blocks.
class CredentialDetailSheet extends StatefulWidget {
  final String walletMasterHex;
  final String chainName;
  final String kind;
  final VoidCallback onRemoved;

  const CredentialDetailSheet({
    super.key,
    required this.walletMasterHex,
    required this.chainName,
    required this.kind,
    required this.onRemoved,
  });

  @override
  State<CredentialDetailSheet> createState() => _CredentialDetailSheetState();
}

class _CredentialDetailSheetState extends State<CredentialDetailSheet> {
  rust.WalletCredentialDetail? _detail;
  bool _loading = true;
  String? _error;
  bool _removing = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final d = await rust.walletGetCredential(
        masterHex: widget.walletMasterHex,
        chainName: widget.chainName,
      );
      if (mounted) setState(() { _detail = d; _loading = false; });
    } catch (e) {
      if (mounted) setState(() { _error = e.toString(); _loading = false; });
    }
  }

  Future<void> _confirmRemove() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text('Remove credential'),
        content: const Text(
          'This appends a tombstone to the chain.\n'
          'The entry will no longer appear in the wallet.',
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

  String get _title => switch (widget.kind) {
        'yubikey-ref' => _detail?.label ?? 'YubiKey',
        _ => _detail?.label.isNotEmpty == true ? _detail!.label : 'SSH Key',
      };

  String get _badgeLabel => switch (widget.kind) {
        'yubikey-ref' => 'yubikey',
        _ => 'ssh',
      };

  Color get _badgeColor => widget.kind == 'yubikey-ref'
      ? const Color(0xFF30D158)
      : const Color(0xFF0A84FF);

  Color get _badgeBg => widget.kind == 'yubikey-ref'
      ? const Color(0xFF0A2A12)
      : const Color(0xFF0A1A2A);

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.6,
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

          // ── header ───────────────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 4, 12),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    _title,
                    style: const TextStyle(
                        fontSize: 15, fontWeight: FontWeight.w600),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                // kind badge
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
                  decoration: BoxDecoration(
                    color: _badgeBg,
                    borderRadius: BorderRadius.circular(5),
                  ),
                  child: Text(
                    _badgeLabel,
                    style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        color: _badgeColor),
                  ),
                ),
                const SizedBox(width: 4),
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
                        onPressed: _error == null ? _confirmRemove : null,
                      ),
              ],
            ),
          ),
          const Divider(height: 1),

          // ── body ─────────────────────────────────────────────────────────
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : _error != null
                    ? Center(
                        child: Padding(
                          padding: const EdgeInsets.all(24),
                          child: Text(_error!,
                              style: const TextStyle(
                                  color: Color(0xFFFF453A))),
                        ),
                      )
                    : ListView(
                        controller: ctrl,
                        padding: const EdgeInsets.all(16),
                        children: _buildContent(),
                      ),
          ),
        ],
      ),
    );
  }

  List<Widget> _buildContent() {
    final d = _detail;
    if (d == null) return [];

    if (widget.kind == 'yubikey-ref') {
      return [
        // Card AID
        _SectionLabel('Card AID'),
        _MonoBlock(value: d.displayId),
        const SizedBox(height: 20),

        // Auth-slot SSH pubkey
        if (d.pubkeyText != null) ...[
          _CopyableBlock(
            label: 'OpenSSH (authorized_keys)',
            value: d.pubkeyText!,
          ),
        ] else ...[
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFF1C1C1E),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFF3A3A3C)),
            ),
            child: Row(
              children: const [
                Icon(Icons.credit_card_outlined,
                    size: 16, color: Color(0xFF8E8E93)),
                SizedBox(width: 8),
                Text(
                  'Connect the YubiKey to show its SSH public key.',
                  style: TextStyle(
                      fontSize: 12, color: Color(0xFF8E8E93)),
                ),
              ],
            ),
          ),
        ],
      ];
    }

    // SSH key
    return [
      _SectionLabel('Fingerprint'),
      _MonoBlock(value: d.displayId),
      const SizedBox(height: 20),
      if (d.pubkeyText != null)
        _CopyableBlock(
          label: 'OpenSSH (authorized_keys)',
          value: d.pubkeyText!,
        ),
    ];
  }
}

// ── Shared widgets ────────────────────────────────────────────────────────────

class _SectionLabel extends StatelessWidget {
  final String label;
  const _SectionLabel(this.label);

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(bottom: 6),
        child: Text(
          label.toUpperCase(),
          style: const TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: Color(0xFF8E8E93),
              letterSpacing: 0.5),
        ),
      );
}

class _MonoBlock extends StatelessWidget {
  final String value;
  const _MonoBlock({required this.value});

  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: const Color(0xFF1C1C1E),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: const Color(0xFF3A3A3C)),
        ),
        child: SelectableText(
          value,
          style: const TextStyle(
              fontFamily: 'monospace',
              fontSize: 12,
              color: Color(0xFFD1D1D6)),
        ),
      );
}

class _CopyableBlock extends StatelessWidget {
  final String label;
  final String value;
  const _CopyableBlock({required this.label, required this.value});

  @override
  Widget build(BuildContext context) => Column(
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
                icon: const Icon(Icons.copy_outlined,
                    color: Color(0xFF0A84FF)),
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
