import 'package:flutter/material.dart';

// ── Cache-timeout tile ────────────────────────────────────────────────────────

class SettingsTimeoutTile extends StatelessWidget {
  const SettingsTimeoutTile({
    super.key,
    required this.current,
    required this.onChanged,
  });

  final int? current;
  final ValueChanged<int?> onChanged;

  static const _options = <(int?, String)>[
    (null, 'Never'),
    (1, '1 minute'),
    (5, '5 minutes'),
    (15, '15 minutes'),
    (30, '30 minutes'),
    (60, '1 hour'),
  ];

  String get _label => _options
      .firstWhere((e) => e.$1 == current, orElse: () => (null, 'Never'))
      .$2;

  void _pick(BuildContext context) {
    showDialog<int?>(
      context: context,
      builder: (ctx) => SimpleDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text(
          'Cache timeout',
          style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
        ),
        children: _options
            .map(
              (opt) => RadioListTile<int?>(
                value: opt.$1,
                groupValue: current,
                title: Text(opt.$2, style: const TextStyle(fontSize: 14)),
                activeColor: const Color(0xFF0A84FF),
                onChanged: (v) {
                  Navigator.pop(ctx);
                  onChanged(v);
                },
              ),
            )
            .toList(),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListTile(
      tileColor: const Color(0xFF2C2C2E),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      title: const Text('Cache timeout', style: TextStyle(fontSize: 15)),
      subtitle: const Text(
        'Clear credentials after last sign',
        style: TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            _label,
            style: const TextStyle(fontSize: 13, color: Color(0xFF8E8E93)),
          ),
          const SizedBox(width: 4),
          const Icon(Icons.chevron_right, size: 18, color: Color(0xFF8E8E93)),
        ],
      ),
      onTap: () => _pick(context),
    );
  }
}
