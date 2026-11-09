import Cocoa
import FlutterMacOS
import LocalAuthentication
import LocalAuthenticationEmbeddedUI

class TouchIdHudPanel: NSPanel {
  var onCancel: (() -> Void)?

  override var canBecomeKey: Bool {
    return true
  }

  override func cancelOperation(_ sender: Any?) {
    onCancel?()
  }

  override func keyDown(with event: NSEvent) {
    if event.keyCode == 53 { // ESC key
      onCancel?()
    } else {
      super.keyDown(with: event)
    }
  }
}

class MainFlutterWindow: NSWindow {
  private var currentAuthContext: LAContext?
  private var authPanel: TouchIdHudPanel?
  private var previousFrontmostApp: NSRunningApplication?
  private var isAuthenticating: Bool = false

  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)

    setupNativeTouchIdChannel(controller: flutterViewController)

    super.awakeFromNib()
  }

  private func setupNativeTouchIdChannel(controller: FlutterViewController) {
    let channel = FlutterMethodChannel(
      name: "p43/native_touch_id",
      binaryMessenger: controller.engine.binaryMessenger
    )

    channel.setMethodCallHandler { [weak self, weak controller] (call: FlutterMethodCall, result: @escaping FlutterResult) in
      guard let self = self, let _ = controller else {
        result(FlutterError(code: "UNAVAILABLE", message: "Window closed", details: nil))
        return
      }

      switch call.method {
      case "isAvailable":
        let context = LAContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        result(canEvaluate)

      case "bringToFrontAndSavePrevious":
        if self.previousFrontmostApp == nil,
           let frontApp = NSWorkspace.shared.frontmostApplication,
           frontApp.bundleIdentifier != Bundle.main.bundleIdentifier {
          self.previousFrontmostApp = frontApp
        }
        result(nil)

      case "restorePreviousApp":
        let prevApp = self.previousFrontmostApp
        self.previousFrontmostApp = nil

        if let app = prevApp {
          if #available(macOS 14.0, *) {
            NSApp.yieldActivation(to: app)
            app.activate()
          } else {
            app.activate(options: .activateIgnoringOtherApps)
          }
        }
        result(nil)

      case "authenticate":
        guard !self.isAuthenticating else {
          result(FlutterError(code: "BUSY", message: "Biometric authentication already in progress", details: nil))
          return
        }

        guard let args = call.arguments as? [String: Any],
              let reason = args["reason"] as? String else {
          result(FlutterError(code: "INVALID_ARGS", message: "Missing reason", details: nil))
          return
        }

        self.isAuthenticating = true

        // Capture previous frontmost app if not already recorded
        if self.previousFrontmostApp == nil,
           let frontApp = NSWorkspace.shared.frontmostApplication,
           frontApp.bundleIdentifier != Bundle.main.bundleIdentifier {
          self.previousFrontmostApp = frontApp
        }

        let context = LAContext()
        context.localizedFallbackTitle = "" // Hides fallback password button
        self.currentAuthContext = context

        // Get main screen and calculate horizontal card: 330 x 84 pt centered on screen
        guard let screen = NSScreen.main ?? self.screen else {
          result(false)
          return
        }

        let cardWidth: CGFloat = 330.0
        let cardHeight: CGFloat = 84.0
        let originX = round(screen.visibleFrame.midX - (cardWidth / 2.0))
        let originY = round(screen.visibleFrame.midY - (cardHeight / 2.0))
        let windowRect = NSRect(x: originX, y: originY, width: cardWidth, height: cardHeight)

        // Create sleek floating HUD card panel
        let panel = TouchIdHudPanel(
          contentRect: windowRect,
          styleMask: [.borderless, .nonactivatingPanel],
          backing: .buffered,
          defer: false
        )
        panel.isFloatingPanel = true
        panel.level = .floating
        panel.backgroundColor = .clear
        panel.isOpaque = false
        panel.hasShadow = true

        let visualEffect = NSVisualEffectView(frame: NSRect(origin: .zero, size: windowRect.size))
        visualEffect.material = .hudWindow
        visualEffect.state = .active
        visualEffect.wantsLayer = true
        visualEffect.layer?.cornerRadius = 18
        visualEffect.layer?.masksToBounds = true
        visualEffect.layer?.borderWidth = 0.5
        visualEffect.layer?.borderColor = NSColor.white.withAlphaComponent(0.15).cgColor
        panel.contentView = visualEffect

        // 1. Left: App Icon (44x44, squircle rounded corners)
        let appIconView = NSImageView()
        appIconView.translatesAutoresizingMaskIntoConstraints = false
        let icon = NSImage(named: NSImage.applicationIconName) ?? NSWorkspace.shared.icon(forFile: Bundle.main.bundlePath)
        appIconView.image = icon
        appIconView.imageScaling = .scaleProportionallyUpOrDown
        appIconView.wantsLayer = true
        appIconView.layer?.cornerRadius = 10
        appIconView.layer?.masksToBounds = true

        // 2. Middle: Title + Subtitle
        let titleLabel = NSTextField(labelWithString: "p43")
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.font = NSFont.systemFont(ofSize: 15, weight: .bold)
        titleLabel.textColor = .labelColor

        let displayReason = reason.replacingOccurrences(of: "p43 ", with: "")
        let reasonLabel = NSTextField(labelWithString: displayReason)
        reasonLabel.translatesAutoresizingMaskIntoConstraints = false
        reasonLabel.font = NSFont.systemFont(ofSize: 12, weight: .regular)
        reasonLabel.textColor = .secondaryLabelColor
        reasonLabel.lineBreakMode = .byTruncatingTail
        reasonLabel.maximumNumberOfLines = 1

        let textStack = NSStackView(views: [titleLabel, reasonLabel])
        textStack.orientation = .vertical
        textStack.alignment = .leading
        textStack.spacing = 2
        textStack.translatesAutoresizingMaskIntoConstraints = false
        textStack.setContentHuggingPriority(.defaultLow, for: .horizontal)

        // 3. Right: Apple's native LAAuthenticationView Touch ID control
        let authView = LAAuthenticationView(context: context)
        authView.translatesAutoresizingMaskIntoConstraints = false

        // Horizontal card layout: [AppIcon]  [Text Stack]  [Touch ID Glyph]
        let cardStack = NSStackView(views: [appIconView, textStack, authView])
        cardStack.orientation = .horizontal
        cardStack.alignment = .centerY
        cardStack.spacing = 16
        cardStack.translatesAutoresizingMaskIntoConstraints = false
        visualEffect.addSubview(cardStack)

        NSLayoutConstraint.activate([
          appIconView.widthAnchor.constraint(equalToConstant: 44),
          appIconView.heightAnchor.constraint(equalToConstant: 44),
          cardStack.leadingAnchor.constraint(equalTo: visualEffect.leadingAnchor, constant: 18),
          cardStack.trailingAnchor.constraint(equalTo: visualEffect.trailingAnchor, constant: -18),
          cardStack.centerYAnchor.constraint(equalTo: visualEffect.centerYAnchor),
        ])

        var finished = false
        let finishAuth = { (success: Bool) in
          guard !finished else { return }
          finished = true
          self.isAuthenticating = false
          panel.close()
          self.authPanel = nil
          self.currentAuthContext = nil

          if let prevApp = self.previousFrontmostApp {
            self.previousFrontmostApp = nil
            if #available(macOS 14.0, *) {
              NSApp.yieldActivation(to: prevApp)
              prevApp.activate()
            } else {
              prevApp.activate(options: .activateIgnoringOtherApps)
            }
          }

          result(success)
        }

        panel.onCancel = {
          context.invalidate()
          DispatchQueue.main.async {
            finishAuth(false)
          }
        }

        self.authPanel?.close()
        self.authPanel = panel
        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
          DispatchQueue.main.async {
            finishAuth(success)
          }
        }

      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }
}
