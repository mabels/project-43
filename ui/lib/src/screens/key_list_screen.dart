import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';
import 'generate_key_screen.dart';

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

  Future<void> _openGenerate() async {
    final didGenerate = await Navigator.push<bool>(
      context,
      MaterialPageRoute(builder: (_) => const GenerateKeyScreen()),
    );
    if (didGenerate == true) _reload();
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
            itemBuilder: (context, i) => _KeyCard(key: ValueKey(keys[i].fingerprint), info: keys[i]),
          );
        },
      ),
    );
  }
}

// ── Key card ──────────────────────────────────────────────────────────────────

class _KeyCard extends StatelessWidget {
  const _KeyCard({super.key, required this.info});

  final KeyInfo info;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: const Color(0xFF2C2C2E),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF3A3A3C)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  info.uid,
                  style: const TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const SizedBox(width: 8),
              _Badge(
                label: info.hasSecret ? 'sec' : 'pub',
                color: info.hasSecret
                    ? const Color(0xFFF5A623)
                    : const Color(0xFF30D158),
                background: info.hasSecret
                    ? const Color(0xFF3A2A0A)
                    : const Color(0xFF1A2A1A),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Row(
            children: [
              _Label(info.algo),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  info.fingerprint,
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 10,
                    color: cs.onSurface.withValues(alpha: 0.45),
                    letterSpacing: 0.4,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _Badge extends StatelessWidget {
  const _Badge({
    required this.label,
    required this.color,
    required this.background,
  });

  final String label;
  final Color color;
  final Color background;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.w700,
          color: color,
          letterSpacing: 0.5,
        ),
      ),
    );
  }
}

class _Label extends StatelessWidget {
  const _Label(this.text);
  final String text;

  @override
  Widget build(BuildContext context) {
    return Text(
      text,
      style: TextStyle(
        fontSize: 11,
        color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.5),
      ),
    );
  }
}

// ── Empty / error states ──────────────────────────────────────────────────────

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
              color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.5),
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
