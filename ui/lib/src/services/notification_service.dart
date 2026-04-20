import 'package:flutter_local_notifications/flutter_local_notifications.dart';

/// Thin singleton wrapper around [FlutterLocalNotificationsPlugin].
///
/// Call [init] once at startup.  Call [showSignRequest] whenever an
/// `ssh.sign_request` arrives and the user has notifications enabled.
class NotificationService {
  NotificationService._();
  static final NotificationService instance = NotificationService._();

  final FlutterLocalNotificationsPlugin _plugin =
      FlutterLocalNotificationsPlugin();
  bool _initialized = false;

  Future<void> init() async {
    if (_initialized) return;

    const macOsSettings = DarwinInitializationSettings(
      requestAlertPermission: true,
      requestBadgePermission: false,
      requestSoundPermission: false,
    );
    const androidSettings =
        AndroidInitializationSettings('@mipmap/ic_launcher');
    const linuxSettings =
        LinuxInitializationSettings(defaultActionName: 'Open');

    const initSettings = InitializationSettings(
      macOS: macOsSettings,
      iOS: DarwinInitializationSettings(
        requestAlertPermission: true,
        requestBadgePermission: false,
        requestSoundPermission: false,
      ),
      android: androidSettings,
      linux: linuxSettings,
    );

    await _plugin.initialize(settings: initSettings);
    _initialized = true;
  }

  /// Show a banner notification for an incoming sign request.
  ///
  /// [keyLabel] is the display string shown in the tile (uid + optional card
  /// suffix).  [algo] is the algorithm badge string.  [fingerprint] is used as
  /// a stable notification ID so a rapid flood of requests for the same key
  /// replaces rather than stacks.
  Future<void> showSignRequest({
    required String keyLabel,
    required String algo,
    required String fingerprint,
  }) async {
    if (!_initialized) return;

    const macOsDetails = DarwinNotificationDetails(
      presentAlert: true,
      presentBadge: false,
      presentSound: false,
    );
    const androidDetails = AndroidNotificationDetails(
      'p43_sign_requests',
      'Sign requests',
      channelDescription: 'Notifications for incoming SSH sign requests',
      importance: Importance.high,
      priority: Priority.high,
      showWhen: false,
    );
    const linuxDetails = LinuxNotificationDetails(
      urgency: LinuxNotificationUrgency.normal,
    );
    const details = NotificationDetails(
      macOS: macOsDetails,
      iOS: macOsDetails,
      android: androidDetails,
      linux: linuxDetails,
    );

    final body = keyLabel.isNotEmpty ? '$keyLabel ($algo)' : fingerprint;

    // Use a stable ID derived from the fingerprint so repeated requests for
    // the same key replace the previous banner instead of stacking.
    final id = fingerprint.hashCode & 0x7FFFFFFF;

    await _plugin.show(
      id: id,
      title: 'Sign request',
      body: body,
      notificationDetails: details,
    );
  }
}
