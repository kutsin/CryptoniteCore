import Foundation
import CommonCrypto.CommonCryptor

extension Cryptor {
    public enum Operation {
        case encrypt
        case decrypt
        
        var rawValue: CCOperation {
            switch self {
            case .encrypt: return CCOperation(kCCEncrypt)
            case .decrypt: return CCOperation(kCCDecrypt)
            }
        }
    }
}
