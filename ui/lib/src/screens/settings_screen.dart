import 'package:flutter/material.dart';
import '../services/settings_service.dart';
import 'matrix_login_screen.dart';
import 'matrix_room_list_screen.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({
    super.key,
    required this.loggedIn,
    required this.onLoggedIn,
    required this.onLoggedOut,
  });

  final bool loggedIn;
  final VoidCallback onLoggedIn;
  final VoidCallback onLoggedOut;

  void _openMatrix(BuildContext context) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => loggedIn
            ? MatrixRoomListScreen(onLoggedOut: onLoggedOut)
            : MatrixLoginScreen(onLoggedIn: onLoggedIn),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF1C1C1E),
        title: const Text('Settings'),
      ),
      body: ListenableBuilder(
        listenable: SettingsService.instance,
        builder: (context, _) {
          final s = SettingsService.instance.settings;
          return ListView(
            children: [
              _SectionHeader('Matrix'),
              ListTile(
                tileColor: const Color(0xFF2C2C2E),
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                leading: Icon(
                  Icons.chat_bubble_outline,
                  color: loggedIn
                      ? const Color(0xFF30D158)
                      : const Color(0xFF8E8E93),
                  size: 20,
                ),
                title: const Text('Matrix', style: TextStyle(fontSize: 15)),
                subtitle: Text(
                  loggedIn ? 'Connected' : 'Not connected',
                  style: TextStyle(
                    fontSize: 12,
                    color: loggedIn
                        ? const Color(0xFF30D158)
                        : const Color(0xFF8E8E93),
                  ),
                ),
                trailing: const Icon(Icons.chevron_right,
                    size: 18, color: Color(0xFF8E8E93)),
                onTap: () => _openMatrix(context),
              ),
              const Divider(height: 32),
              _SectionHeader('Agent'),
              _SettingsTile(
                title: 'Auto-approve cached keys',
                subtitle: s.autoApproveWhenCached
                    ? 'Sign requests are approved automatically when the '
                        'passphrase is already in memory.'
                    : 'Every sign request requires explicit approval, '
                        'even when the passphrase is cached.',
                value: s.autoApproveWhenCached,
                onChanged: (v) => SettingsService.instance.save(
                  s.copyWith(autoApproveWhenCached: v),
                ),
              ),
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 8, 16, 4),
                child: Text(
                  'When biometric approval is enabled in a future release, '
                  'auto-approve will trigger a biometric prompt instead of '
                  'silently signing.',
                  style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
                ),
              ),
              const SizedBox(height: 8),
              _SettingsTile(
                title: 'Cache decrypted key',
                subtitle: s.cacheDecryptedKey
                    ? 'Private key is kept decrypted in memory after first '
                        'approval. Auto-approve completes in milliseconds.'
                    : 'Private key is re-derived from your passphrase on '
                        'every sign (~9 s on this hardware). Slower but no '
                        'in-memory key material.',
                value: s.cacheDecryptedKey,
                onChanged: (v) => SettingsService.instance.save(
                  s.copyWith(cacheDecryptedKey: v),
                ),
              ),
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 8, 16, 4),
                child: Text(
                  'When enabled, the decrypted Ed25519 key bytes live in '
                  'process memory for the session — the same trade-off '
                  'ssh-agent makes. Disable to re-run the KDF on every sign.',
                  style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
                ),
              ),
              const SizedBox(height: 8),
              _TimeoutTile(
                current: s.cacheTimeoutMinutes,
                onChanged: (v) => SettingsService.instance.save(
                  s.copyWith(cacheTimeoutMinutes: v),
                ),
              ),
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 8, 16, 4),
                child: Text(
                  'Caches are always cleared on screen-lock / app background, '
                  'regardless of this timer.',
                  style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
                ),
              ),
              const Divider(height: 32),
              _SectionHeader('Notifications'),
              _SettingsTile(
                title: 'Sign request notifications',
                subtitle: s.notifyOnSignRequest
                    ? 'A banner is shown for every incoming sign request and '
                        'the Agent tab is brought into focus.'
                    : 'No system notification is shown. The Agent tab is '
                        'still brought into focus when a request arrives.',
                value: s.notifyOnSignRequest,
                onChanged: (v) => SettingsService.instance.save(
                  s.copyWith(notifyOnSignRequest: v),
                ),
              ),
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 8, 16, 4),
                child: Text(
                  'System notifications require macOS notification permission '
                  'for p43. You can manage this in System Settings → '
                  'Notifications → p43.',
                  style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
                ),
              ),
              const SizedBox(height: 8),
              const Divider(height: 32),
              _SectionHeader('Telemetry'),
              _OtelEndpointTile(
                current: s.otelEndpoint,
                onChanged: (v) => SettingsService.instance.save(
                  s.copyWith(otelEndpoint: v),
                ),
              ),
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 8, 16, 4),
                child: Text(
                  'Leave empty to disable tracing (local fmt mode). '
                  'Set to your OTel Collector URL to export spans. '
                  'Changes take effect on the next app launch.',
                  style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
                ),
              ),
              const SizedBox(height: 8),
              const Divider(height: 32),
            ],
          );
        },
      ),
    );
  }
}

// ── Section header ────────────────────────────────────────────────────────────

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 6),
      child: Text(
        title.toUpperCase(),
        style: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w600,
          color: Color(0xFF8E8E93),
          letterSpacing: 0.6,
        ),
      ),
    );
  }
}

// ── Cache-timeout tile ────────────────────────────────────────────────────────

class _TimeoutTile extends StatelessWidget {
  const _TimeoutTile({required this.current, required this.onChanged});

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

  String get _label =>
      _options.firstWhere((e) => e.$1 == current, orElse: () => (null, 'Never')).$2;

  void _pick(BuildContext context) {
    showDialog<int?>(
      context: context,
      builder: (ctx) => SimpleDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text('Cache timeout',
            style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
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
      title: const Text('Cache timeout',
          style: TextStyle(fontSize: 15)),
      subtitle: const Text(
        'Clear credentials after last sign',
        style: TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(_label,
              style: const TextStyle(fontSize: 13, color: Color(0xFF8E8E93))),
          const SizedBox(width: 4),
          const Icon(Icons.chevron_right, size: 18, color: Color(0xFF8E8E93)),
        ],
      ),
      onTap: () => _pick(context),
    );
  }
}

// ── OTel endpoint tile ────────────────────────────────────────────────────────

class _OtelEndpointTile extends StatelessWidget {
  const _OtelEndpointTile({required this.current, required this.onChanged});

  final String current;
  final ValueChanged<String> onChanged;

  void _edit(BuildContext context) {
    final controller = TextEditingController(text: current);
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF2C2C2E),
        title: const Text('OTel Collector URL',
            style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
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
      trailing: const Icon(Icons.chevron_right, size: 18, color: Color(0xFF8E8E93)),
      onTap: () => _edit(context),
    );
  }
}

// ── Toggle tile ───────────────────────────────────────────────────────────────

class _SettingsTile extends StatelessWidget {
  const _SettingsTile({
    required this.title,
    required this.subtitle,
    required this.value,
    required this.onChanged,
  });

  final String title;
  final String subtitle;
  final bool value;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    return SwitchListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      tileColor: const Color(0xFF2C2C2E),
      title: Text(title, style: const TextStyle(fontSize: 15)),
      subtitle: Text(
        subtitle,
        style: const TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
      ),
      value: value,
      activeColor: const Color(0xFF30D158),
      onChanged: onChanged,
    );
  }
}
