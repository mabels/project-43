import 'package:flutter/material.dart';

// ── OTel endpoint tile ────────────────────────────────────────────────────────

class SettingsOtelEndpointTile extends StatelessWidget {
  const SettingsOtelEndpointTile({
    super.key,
    required this.current,
    required this.onChanged,
  });

  final String current;
  final ValueChanged<String> onChanged;

  void _edit(BuildContext context) {
    final controller = TextEditingController(text: current);
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text(
          'OTel Collector URL',
          style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
        ),
        content: TextField(
          controller: controller,
          autofocus: true,
          keyboardType: TextInputType.url,
          style: const TextStyle(fontSize: 14),
          decoration: const InputDecoration(
            hintText: 'https://otel.adviser.com',
            hintStyle: TextStyle(color: Color(0xFF8E8E93)),
            border: OutlineInputBorder(),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              Navigator.pop(ctx);
              onChanged(controller.text.trim());
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isEmpty = current.isEmpty;
    return ListTile(
      tileColor: const Color(0xFF2C2C2E),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      leading: Icon(
        Icons.sensors,
        color: isEmpty ? const Color(0xFF8E8E93) : const Color(0xFF30D158),
        size: 20,
      ),
      title: const Text('Collector endpoint', style: TextStyle(fontSize: 15)),
      subtitle: Text(
        isEmpty ? 'Disabled (local mode)' : current,
        style: TextStyle(
          fontSize: 12,
          color: isEmpty ? const Color(0xFF8E8E93) : const Color(0xFF30D158),
        ),
        overflow: TextOverflow.ellipsis,
      ),
      trailing: const Icon(
        Icons.chevron_right,
        size: 18,
        color: Color(0xFF8E8E93),
      ),
      onTap: () => _edit(context),
    );
  }
}
