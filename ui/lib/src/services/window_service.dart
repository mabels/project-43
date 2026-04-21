import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:window_manager/window_manager.dart';

/// Platform-aware service for bringing the app window to the foreground.
///
/// Desktop (macOS / Windows / Linux)
///   Uses [window_manager] to show and focus the native window.  Must be
///   initialised once at startup via [init].
///
/// Mobile (Android / iOS)
///   No programmatic foreground API exists; the OS notification that is
///   already sent by [NotificationService] serves as the tap-to-open path.
///   [bringToFront] is a no-op on these platforms.
class WindowService {
  WindowService._();
  static final WindowService instance = WindowService._();

  static bool get _isDesktop =>
      !kIsWeb && (Platform.isMacOS || Platform.isWindows || Platform.isLinux);

  /// Call once in [main] before [runApp], on desktop only.
  Future<void> init() async {
    if (!_isDesktop) return;
    await windowManager.ensureInitialized();
    const options = WindowOptions(
      titleBarStyle: TitleBarStyle.normal,
    );
    await windowManager.waitUntilReadyToShow(options);
  }

  /// Bring the window to the foreground.
  ///
  /// On desktop: shows the window if minimised/hidden and gives it focus.
  /// On mobile: no-op (notification tap is the foreground mechanism).
  Future<void> bringToFront() async {
    if (!_isDesktop) return;
    try {
      await windowManager.show();
      await windowManager.focus();
    } catch (_) {
      // Best-effort — never crash the sign flow over a window hint.
    }
  }
}
