import SwiftUI

// SwiftUI's LabeledContent needs macOS 13; this module-local stand-in
// shadows it so MenuView compiles unchanged on Monterey. A fixed label
// column approximates the native alignment inside the 340 pt window.
struct LabeledContent<Content: View>: View {
    private let label: String
    private let content: Content

    init(_ label: String, @ViewBuilder content: () -> Content) {
        self.label = label
        self.content = content()
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 88, alignment: .trailing)
            content
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
