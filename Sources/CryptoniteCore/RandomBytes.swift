import Foundation
import CommonCrypto.Random

public enum RandomBytes {
    static func generateBytes(count: Int) throws -> [Int8] {
        var bytes = [Int8](repeating: 0, count: count)
        let status = CCRandomGenerateBytes(&bytes, bytes.count)
        try Cryptor.Error.verify(status)
        return bytes
    }
    
    static func generateData(count: Int) throws -> Data {
        let bytes = try generateBytes(count: count)
        return Data(bytes: bytes, count: bytes.count)
    }
}
