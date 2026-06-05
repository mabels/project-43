import 'package:flutter/material.dart';
import 'keys/add_credential_sheet.dart';
import 'keys/credentials_tab.dart';
import 'keys/key_import_sheet.dart';

/// Keys page — wallet credentials displayed with the same structure as the
/// old key-store page (section header + action buttons + credential cards).
class KeyListScreen extends StatefulWidget {
  final String? walletMasterHex;
  const KeyListScreen({super.key, this.walletMasterHex});

  @override
  State<KeyListScreen> createState() => _KeyListScreenState();
}

class _KeyListScreenState extends State<KeyListScreen> {
  final _credKey = GlobalKey<_CredentialsTabWrapperState>();

  void _reload() => _credKey.currentState?.reload();

  // ── action buttons ──────────────────────────────────────────────────────────

  void _addYubiKey() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1C1C1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => AddCredentialSheet(
        walletMasterHex: widget.walletMasterHex!,
        parentContext: context,
        onAdded: _reload,
        initialKind: AddCredentialKind.yubikey,
      ),
    );
  }

  void _openImportSheet() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1C1C1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => KeyImportSheet(
        walletMasterHex: widget.walletMasterHex!,
        onImported: _reload,
      ),
    );
  }

  // ── build ────────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final unlocked = widget.walletMasterHex != null;

    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF1C1C1E),
        title: const Text(
          'Keys',
          style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600),
        ),
      ),
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // ── section header — mirrors "p43 Key Store" row ──────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 8, 0),
            child: Row(
              children: [
                const Text(
                  'p43',
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                    color: Color(0xFF0A84FF),
                  ),
                ),
                const SizedBox(width: 6),
                const Text(
                  'Wallet',
                  style: TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
                ),
                const Spacer(),
                if (unlocked) ...[
                  // Add YubiKey reference
                  IconButton(
                    icon: const Icon(Icons.credit_card_outlined, size: 20),
                    tooltip: 'Add YubiKey reference',
                    onPressed: _addYubiKey,
                    color: const Color(0xFF8E8E93),
                  ),
                  // Import SSH or OpenPGP key
                  IconButton(
                    icon: const Icon(Icons.download_outlined, size: 20),
                    tooltip: 'Import SSH / OpenPGP key',
                    onPressed: _openImportSheet,
                    color: const Color(0xFF8E8E93),
                  ),
                ],
              ],
            ),
          ),

          // ── credential list ───────────────────────────────────────────────
          Expanded(
            child: _CredentialsTabWrapper(
              key: _credKey,
              walletMasterHex: widget.walletMasterHex,
              onReload: _reload,
            ),
          ),
        ],
      ),
    );
  }
}

// ── wrapper that exposes reload() ─────────────────────────────────────────────

class _CredentialsTabWrapper extends StatefulWidget {
  final String? walletMasterHex;
  final VoidCallback onReload;
  const _CredentialsTabWrapper({
    super.key,
    this.walletMasterHex,
    required this.onReload,
  });

  @override
  State<_CredentialsTabWrapper> createState() =>
      _CredentialsTabWrapperState();
}

class _CredentialsTabWrapperState extends State<_CredentialsTabWrapper> {
  int _epoch = 0;

  void reload() => setState(() => _epoch++);

  @override
  Widget build(BuildContext context) {
    return CredentialsTab(
      key: ValueKey(_epoch),
      walletMasterHex: widget.walletMasterHex,
    );
  }
}
