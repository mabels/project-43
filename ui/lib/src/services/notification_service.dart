import 'dart:async';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

/// Thin singleton wrapper around [FlutterLocalNotificationsPlugin].
///
/// Call [init] once at startup, then [show] whenever a notification is needed.
/// Callers are responsible for composing the text — this service only handles
/// platform plumbing and auto-dismissal.
class NotificationService {
  NotificationService._();
  static final NotificationService instance = NotificationService._();

  final FlutterLocalNotificationsPlugin _plugin =
      FlutterLocalNotificationsPlugin();
  bool _initialized = false;

  Future<void> init() async {
    if (_initialized) return;

    const darwinSettings = DarwinInitializationSettings(
      requestAlertPermission: true,
      requestBadgePermission: false,
      requestSoundPermission: false,
    );
    const initSettings = InitializationSettings(
      macOS: darwinSettings,
      iOS: darwinSettings,
      android: AndroidInitializationSettings('@mipmap/ic_launcher'),
      linux: LinuxInitializationSettings(defaultActionName: 'Open'),
    );

    await _plugin.initialize(settings: initSettings);
    _initialized = true;
  }

  /// Show a notification banner.
  ///
  /// [title] and [body] are the visible text.
  ///
  /// [stableId] is an optional string whose hash is used as the numeric
  /// notification ID.  Repeated calls with the same [stableId] replace the
  /// previous banner instead of stacking (e.g. pass a fingerprint or device ID).
  /// Defaults to a hash of `title + body`.
  ///
  /// [closeAfter] auto-dismisses the notification.  Defaults to 8 seconds.
  /// Android and Linux use platform-native timeout fields; macOS and iOS
  /// schedule a `cancel()` call (no native auto-dismiss API exists there).
  ///
  /// [channelId] / [channelName] are Android notification channel identifiers.
  Future<void> show({
    required String title,
    required String body,
    String? stableId,
    Duration closeAfter = const Duration(seconds: 8),
    String channelId = 'p43_notifications',
    String channelName = 'Notifications',
    String channelDescription = 'p43 notifications',
  }) async {
    if (!_initialized) return;

    final id = (stableId ?? '$title\x00$body').hashCode & 0x7FFFFFFF;

    final details = NotificationDetails(
      macOS: const DarwinNotificationDetails(
        presentAlert: true, // legacy path (macOS < 12)
        presentBanner: true, // banner drop-down (macOS 12+)
        presentList: true, // show in Notification Centre list
        presentBadge: false,
        presentSound: false,
      ),
      iOS: const DarwinNotificationDetails(
        presentAlert: true,
        presentBanner: true,
        presentList: true,
        presentBadge: false,
        presentSound: false,
      ),
      android: AndroidNotificationDetails(
        channelId,
        channelName,
        channelDescription: channelDescription,
        importance: Importance.high,
        priority: Priority.high,
        showWhen: false,
        timeoutAfter: closeAfter.inMilliseconds,
      ),
      linux: LinuxNotificationDetails(
        urgency: LinuxNotificationUrgency.normal,
        timeout: LinuxNotificationTimeout(closeAfter.inMilliseconds),
      ),
    );

    await _plugin.show(
      id: id,
      title: title,
      body: body,
      notificationDetails: details,
    );
    // Belt-and-suspenders cancel for macOS/iOS (and as a fallback everywhere).
    Future.delayed(closeAfter, () => _plugin.cancel(id: id));
  }
}
