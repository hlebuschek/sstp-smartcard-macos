import Combine
import SwiftUI

@main
struct SSTPApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = TunnelModel()

    var body: some Scene {
        // A window rather than only a menu bar item: on a notched Mac with a
        // busy menu bar new status items land in the hidden overflow area and
        // are never seen. WindowGroup rather than Window, and NSStatusItem
        // rather than MenuBarExtra: both newer APIs need macOS 13, and the
        // app has to run on Monterey-era Intel Macs.
        WindowGroup("SSTP VPN") {
            MenuView(model: model)
                .onAppear { delegate.attach(model) }
        }
        .commands { CommandGroup(replacing: .newItem) {} }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private let popover = NSPopover()
    private var cancellable: AnyCancellable?
    private weak var model: TunnelModel?

    func attach(_ model: TunnelModel) {
        guard self.model !== model else { return }
        self.model = model

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.target = self
        item.button?.action = #selector(togglePopover)
        statusItem = item

        popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: MenuView(model: model))

        cancellable = model.objectWillChange
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in self?.updateIcon() }
        updateIcon()
    }

    private func updateIcon() {
        guard let model, let button = statusItem?.button else { return }
        let name = model.status.isConnected
            ? "lock.shield.fill"
            : (model.busy ? "lock.shield" : "lock.open")
        button.image = NSImage(systemSymbolName: name, accessibilityDescription: "SSTP VPN")
    }

    @objc private func togglePopover() {
        guard let button = statusItem?.button else { return }
        if popover.isShown {
            popover.performClose(nil)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // No .windowResizability(.contentSize) before macOS 13; the content
        // is fixed-size anyway, so just take the resize handle away.
        DispatchQueue.main.async {
            for window in NSApp.windows where window.styleMask.contains(.titled) {
                window.styleMask.remove(.resizable)
            }
        }
    }
}
