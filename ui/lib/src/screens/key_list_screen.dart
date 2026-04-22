import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'generate_key_screen.dart';
import 'keys/card_import_sheet.dart';
import 'keys/key_card.dart';
import 'keys/key_detail_sheet.dart';
import 'keys/key_import_sheet.dart';

// ── Key list screen ───────────────────────────────────────────────────────────

class KeyListScreen extends StatefulWidget {
  const KeyListScreen({super.key});

  @override
  State<KeyListScreen> createState() => _KeyListScreenState();
}

class _KeyListScreenState extends State<KeyListScreen> {
  late Future<List<KeyInfo>> _keysFuture;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  void _reload() {
    setState(() {
      _keysFuture = listKeys();
    });
  }

  void _showKeyDetail(BuildContext context, KeyInfo info) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1C1C1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => KeyDetailSheet(info: info, onDeleted: _reload),
    );
  }

  Future<void> _openGenerate() async {
    final didGenerate = await Navigator.push<bool>(
      context,
      MaterialPageRoute(builder: (_) => const GenerateKeyScreen()),
    );
    if (didGenerate == true) _reload();
  }

  void _openCardImport() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1C1C1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => CardImportSheet(onImported: _reload),
    );
  }

  void _openImport() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1C1C1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (_) => KeyImportSheet(onImported: _reload),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF1C1C1E),
        title: Row(
          children: [
            Text(
              'p43',
              style: TextStyle(
                fontWeight: FontWeight.w700,
                fontSize: 17,
                color: cs.onSurface,
              ),
            ),
            const SizedBox(width: 8),
            Text(
              'Key Store',
              style: TextStyle(
                fontWeight: FontWeight.w400,
                fontSize: 14,
                color: cs.onSurface.withValues(alpha: 0.5),
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.contactless_outlined),
            tooltip: 'Import from card',
            onPressed: _openCardImport,
          ),
          IconButton(
            icon: const Icon(Icons.download_outlined),
            tooltip: 'Import SSH / OpenPGP key',
            onPressed: _openImport,
          ),
          IconButton(
            icon: const Icon(Icons.add),
            tooltip: 'Generate key',
            onPressed: _openGenerate,
          ),
        ],
      ),
      body: FutureBuilder<List<KeyInfo>>(
        future: _keysFuture,
        builder: (context, snap) {
          if (snap.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snap.hasError) {
            return _ErrorView(message: snap.error.toString());
          }
          final keys = snap.data!;
          if (keys.isEmpty) {
            return _EmptyView(onGenerate: _openGenerate);
          }
          return ListView.separated(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            itemCount: keys.length,
            separatorBuilder: (context, _) => const SizedBox(height: 8),
            itemBuilder: (context, i) => KeyCard(
              key: ValueKey(keys[i].fingerprint),
              info: keys[i],
              onTap: () => _showKeyDetail(context, keys[i]),
            ),
          );
        },
      ),
    );
  }
}

// ── Empty state ───────────────────────────────────────────────────────────────

class _EmptyView extends StatelessWidget {
  const _EmptyView({required this.onGenerate});
  final VoidCallback onGenerate;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text('🔑', style: TextStyle(fontSize: 40)),
          const SizedBox(height: 12),
          const Text(
            'No keys in store.',
            style: TextStyle(fontSize: 15, fontWeight: FontWeight.w500),
          ),
          const SizedBox(height: 6),
          Text(
            'Generate your first key to get started.',
            style: TextStyle(
              fontSize: 13,
              color: Theme.of(
                context,
              ).colorScheme.onSurface.withValues(alpha: 0.5),
            ),
          ),
          const SizedBox(height: 20),
          FilledButton.icon(
            onPressed: onGenerate,
            icon: const Icon(Icons.add, size: 16),
            label: const Text('Generate Key'),
          ),
        ],
      ),
    );
  }
}

// ── Error state ───────────────────────────────────────────────────────────────

class _ErrorView extends StatelessWidget {
  const _ErrorView({required this.message});
  final String message;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Text(
          message,
          style: const TextStyle(color: Color(0xFFFF453A), fontSize: 13),
          textAlign: TextAlign.center,
        ),
      ),
    );
  }
}
