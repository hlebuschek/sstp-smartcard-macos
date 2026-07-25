import SwiftUI

@main
struct SSTPApp: App {
    @StateObject private var model = TunnelModel()

    var body: some Scene {
        // A window rather than only a menu bar item: on a notched Mac with a
        // busy menu bar new status items land in the hidden overflow area and
        // are never seen.
        Window("SSTP VPN", id: "main") {
            MenuView(model: model)
        }
        .windowResizability(.contentSize)
        .commands { CommandGroup(replacing: .newItem) {} }

        MenuBarExtra {
            MenuView(model: model)
        } label: {
            Image(systemName: model.status.isConnected
                  ? "lock.shield.fill"
                  : (model.busy ? "lock.shield" : "lock.open"))
        }
        .menuBarExtraStyle(.window)
    }
}
