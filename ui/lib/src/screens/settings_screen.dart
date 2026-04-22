import 'package:flutter/material.dart';
import '../services/settings_service.dart';
import 'matrix_login_screen.dart';
import 'matrix_room_list_screen.dart';
import 'settings/agent_section.dart';
import 'settings/shared_widgets.dart';
import 'settings/telemetry_section.dart';

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
              // ── Matrix ────────────────────────────────────────────────
              SettingsSectionHeader('Matrix'),
              ListTile(
                tileColor: const Color(0xFF2C2C2E),
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 4,
                ),
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
                trailing: const Icon(
                  Icons.chevron_right,
                  size: 18,
                  color: Color(0xFF8E8E93),
                ),
                onTap: () => _openMatrix(context),
              ),

              // ── Devices ───────────────────────────────────────────────
              const Divider(height: 32),
              SettingsSectionHeader('Devices'),
              _DeviceCertTtlTile(
                current: s.deviceCertTtlDays,
                onChanged: (v) => SettingsService.instance.save(
                  s.copyWith(deviceCertTtlDays: v),
                ),
              ),
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 8, 16, 4),
                child: Text(
                  'How long a device certificate is valid after being issued. '
                  'Devices must re-register when their certificate expires.',
                  style: TextStyle(fontSize: 11, color: Color(0xFF8E8E93)),
                ),
              ),
              const SizedBox(height: 8),

              // ── Agent ─────────────────────────────────────────────────
              const Divider(height: 32),
              SettingsSectionHeader('Agent'),
              SettingsToggleTile(
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
              SettingsToggleTile(
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
              SettingsTimeoutTile(
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

              // ── Notifications ─────────────────────────────────────────
              const Divider(height: 32),
              SettingsSectionHeader('Notifications'),
              SettingsToggleTile(
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

              // ── Telemetry ─────────────────────────────────────────────
              const Divider(height: 32),
              SettingsSectionHeader('Telemetry'),
              SettingsOtelEndpointTile(
                current: s.otelEndpoint,
                onChanged: (v) =>
                    SettingsService.instance.save(s.copyWith(otelEndpoint: v)),
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

// ── Device cert TTL tile ──────────────────────────────────────────────────────

class _DeviceCertTtlTile extends StatelessWidget {
  const _DeviceCertTtlTile({
    required this.current,
    required this.onChanged,
  });

  final int current;
  final ValueChanged<int> onChanged;

  static const _options = [30, 60, 90, 180, 365];

  String _label(int days) {
    if (days == 0) return 'No expiry';
    if (days % 365 == 0) {
      final y = days ~/ 365;
      return '$y ${y == 1 ? 'year' : 'years'}';
    }
    if (days % 30 == 0) {
      final m = days ~/ 30;
      return '$m ${m == 1 ? 'month' : 'months'}';
    }
    return '$days days';
  }

  @override
  Widget build(BuildContext context) {
    return ListTile(
      tileColor: const Color(0xFF2C2C2E),
      contentPadding:
          const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      title: const Text(
        'Certificate validity',
        style: TextStyle(fontSize: 15),
      ),
      subtitle: Text(
        _label(current),
        style: const TextStyle(fontSize: 12, color: Color(0xFF8E8E93)),
      ),
      trailing: const Icon(
        Icons.chevron_right,
        size: 18,
        color: Color(0xFF8E8E93),
      ),
      onTap: () async {
        final picked = await showDialog<int>(
          context: context,
          builder: (ctx) => SimpleDialog(
            backgroundColor: const Color(0xFF2C2C2E),
            title: const Text(
              'Certificate validity',
              style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
            ),
            children: [
              for (final days in _options)
                ListTile(
                  leading: Icon(
                    days == current
                        ? Icons.radio_button_checked
                        : Icons.radio_button_off,
                    size: 18,
                    color: days == current
                        ? const Color(0xFF0A84FF)
                        : const Color(0xFF8E8E93),
                  ),
                  title: Text(
                    _label(days),
                    style: const TextStyle(fontSize: 14),
                  ),
                  onTap: () => Navigator.pop(ctx, days),
                ),
            ],
          ),
        );
        if (picked != null) onChanged(picked);
      },
    );
  }
}
