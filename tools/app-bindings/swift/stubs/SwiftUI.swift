// Linux stand-in for the slice of SwiftUI/Combine that AppState uses. Only for
// type-checking logic; it says nothing about whether view code compiles.
@_exported import Foundation

public protocol ObservableObject: AnyObject {}

public final class ObservableObjectPublisher {
    public init() {}
    public func send() {}
}

extension ObservableObject {
    public var objectWillChange: ObservableObjectPublisher { ObservableObjectPublisher() }
}

@propertyWrapper
public struct Published<Value> {
    public var wrappedValue: Value
    public init(wrappedValue: Value) { self.wrappedValue = wrappedValue }
    public var projectedValue: Published<Value> { self }
}
