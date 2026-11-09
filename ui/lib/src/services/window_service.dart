import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:window_manager/window_manager.dart';

/// Platform-aware service for bringing the app window to the foreground.
///
/// Desktop (macOS / Windows / Linux)
///   Uses [window_manager] or native macOS channel to show and focus the native
///   window while tracking the previous frontmost app for automatic restoration.
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
    const options = WindowOptions(titleBarStyle: TitleBarStyle.normal);
    await windowManager.waitUntilReadyToShow(options);
  }

  /// Bring the window to the foreground.
  ///
  /// On macOS: remembers the currently active app (e.g. Terminal) before focusing.
  /// On other desktop: shows and focuses the window via window_manager.
  Future<void> bringToFront() async {
    if (!_isDesktop) return;
    try {
      if (Platform.isMacOS) {
        const channel = MethodChannel('p43/native_touch_id');
        await channel.invokeMethod('bringToFrontAndSavePrevious');
      } else {
        await windowManager.show();
        await windowManager.focus();
      }
    } catch (_) {
      // Best-effort — never crash the sign flow over a window hint.
    }
  }

  /// Restore focus back to the previously active application (e.g. Terminal).
  Future<void> restorePreviousApp() async {
    if (!Platform.isMacOS) return;
    try {
      const channel = MethodChannel('p43/native_touch_id');
      await channel.invokeMethod('restorePreviousApp');
    } catch (_) {
      // Best-effort
    }
  }
}
