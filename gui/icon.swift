// Renders the application icon from an SF Symbol into an .iconset directory.
import AppKit

let iconset = CommandLine.arguments[1]
try? FileManager.default.createDirectory(
    atPath: iconset, withIntermediateDirectories: true)

let variants: [(String, Int)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32),
    ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256),
    ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]

func symbol(side: CGFloat) -> NSImage? {
    let configuration = NSImage.SymbolConfiguration(pointSize: side, weight: .medium)
    guard let base = NSImage(systemSymbolName: "lock.shield.fill",
                             accessibilityDescription: nil)?
        .withSymbolConfiguration(configuration) else { return nil }
    // Template symbols ignore the current fill colour, so the glyph is used as
    // a mask over a solid white rectangle instead.
    let tinted = NSImage(size: base.size)
    tinted.lockFocus()
    NSColor.white.setFill()
    NSRect(origin: .zero, size: base.size).fill()
    base.draw(at: .zero, from: .zero, operation: .destinationIn, fraction: 1)
    tinted.unlockFocus()
    return tinted
}

for (name, pixels) in variants {
    let side = CGFloat(pixels)
    let image = NSImage(size: NSSize(width: side, height: side))
    image.lockFocus()
    let bounds = NSRect(x: 0, y: 0, width: side, height: side)
    NSColor(calibratedRed: 0.13, green: 0.33, blue: 0.60, alpha: 1).setFill()
    NSBezierPath(roundedRect: bounds.insetBy(dx: side * 0.06, dy: side * 0.06),
                 xRadius: side * 0.20, yRadius: side * 0.20).fill()
    if let glyph = symbol(side: side * 0.52) {
        let size = glyph.size
        glyph.draw(in: NSRect(x: (side - size.width) / 2,
                              y: (side - size.height) / 2,
                              width: size.width, height: size.height))
    }
    image.unlockFocus()

    guard let data = image.tiffRepresentation,
          let bitmap = NSBitmapImageRep(data: data),
          let png = bitmap.representation(using: .png, properties: [:])
    else { continue }
    try png.write(to: URL(fileURLWithPath: "\(iconset)/\(name).png"))
}
