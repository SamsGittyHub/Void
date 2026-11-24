// Renders Void's app icon — an eclipse: a dark disc in a ring of light, on
// deep space — to the PNG path given as the only argument.
//
//   swift tools/icon/make_icon.swift ios/Void/Assets.xcassets/AppIcon.appiconset/AppIcon.png
//
// Drawn in code rather than kept only as a binary, so the icon can be read,
// reviewed and changed like everything else. The stars are random, so two
// runs differ slightly; the committed PNG is the one that ships.
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let size = 1024
let s = CGFloat(size)
let space = CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                    space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!

func color(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> CGColor {
    CGColor(colorSpace: space, components: [r, g, b, a])!
}

// Deep space.
let background = CGGradient(colorsSpace: space,
    colors: [color(0.15, 0.09, 0.34), color(0.05, 0.04, 0.12), color(0.02, 0.02, 0.06)] as CFArray,
    locations: [0, 0.55, 1])!
ctx.drawLinearGradient(background, start: CGPoint(x: s * 0.2, y: s), end: CGPoint(x: s * 0.8, y: 0),
                       options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])

// A few faint stars.
var rng = SystemRandomNumberGenerator()
for _ in 0..<70 {
    let x = CGFloat.random(in: 0...s, using: &rng)
    let y = CGFloat.random(in: 0...s, using: &rng)
    let r = CGFloat.random(in: 1.2...3.4, using: &rng)
    ctx.setFillColor(color(1, 1, 1, CGFloat.random(in: 0.12...0.45, using: &rng)))
    ctx.fillEllipse(in: CGRect(x: x - r, y: y - r, width: 2 * r, height: 2 * r))
}

let center = CGPoint(x: s / 2, y: s / 2)
let radius = s * 0.30

// The corona: light spilling round the disc.
let glow = CGGradient(colorsSpace: space,
    colors: [color(0.55, 0.42, 1.0, 0.85), color(0.40, 0.30, 0.95, 0.35), color(0.30, 0.20, 0.80, 0)] as CFArray,
    locations: [0, 0.35, 1])!
ctx.drawRadialGradient(glow, startCenter: center, startRadius: radius * 0.95, endCenter: center,
                       endRadius: radius * 1.85, options: [])

// The ring, its colour turning round it: short arcs, each a step along the
// palette, since a conic gradient is not available here.
let ringWidth = s * 0.034
let stops: [(CGFloat, CGFloat, CGFloat)] = [(0.70, 0.60, 1.0), (0.43, 0.34, 0.96), (0.36, 0.82, 1.0),
                                           (0.43, 0.34, 0.96), (0.70, 0.60, 1.0)]
let segments = 720
ctx.setLineWidth(ringWidth)
ctx.setLineCap(.butt)
for i in 0..<segments {
    let t = CGFloat(i) / CGFloat(segments)
    let scaled = t * CGFloat(stops.count - 1)
    let k = min(Int(scaled), stops.count - 2)
    let f = scaled - CGFloat(k)
    let a = stops[k], b = stops[k + 1]
    ctx.setStrokeColor(color(a.0 + (b.0 - a.0) * f, a.1 + (b.1 - a.1) * f, a.2 + (b.2 - a.2) * f))
    let start = .pi / 3 + t * 2 * .pi
    ctx.addArc(center: center, radius: radius, startAngle: start,
               endAngle: start + 2 * .pi / CGFloat(segments) * 1.6, clockwise: false)
    ctx.strokePath()
}

// A bright crescent where the light is strongest.
ctx.saveGState()
ctx.addEllipse(in: CGRect(x: center.x - radius - ringWidth / 2, y: center.y - radius - ringWidth / 2,
                          width: 2 * radius + ringWidth, height: 2 * radius + ringWidth))
ctx.clip()
let flare = CGGradient(colorsSpace: space,
    colors: [color(1, 1, 1, 0.9), color(0.8, 0.75, 1, 0)] as CFArray, locations: [0, 1])!
let flareCenter = CGPoint(x: center.x + radius * 0.62, y: center.y + radius * 0.78)
ctx.drawRadialGradient(flare, startCenter: flareCenter, startRadius: 0, endCenter: flareCenter,
                       endRadius: radius * 0.42, options: [])
ctx.restoreGState()

// The void itself.
let inner = radius - ringWidth / 2
ctx.setFillColor(color(0.0, 0.0, 0.02))
ctx.fillEllipse(in: CGRect(x: center.x - inner, y: center.y - inner, width: 2 * inner, height: 2 * inner))

let image = ctx.makeImage()!
let out = URL(fileURLWithPath: CommandLine.arguments[1])
let dest = CGImageDestinationCreateWithURL(out as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(dest, image, nil)
CGImageDestinationFinalize(dest)
print("wrote", out.path)
