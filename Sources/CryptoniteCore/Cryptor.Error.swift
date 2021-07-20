import Foundation
import CommonCrypto.Error

extension Cryptor {
    enum Error: Swift.Error, LocalizedError {
        case errorWithStatus(CCCryptorStatus)
        case errorWithMessage(String)
        
        var description: String {
            switch self {
            case .errorWithStatus(let status):
                switch Int(status) {
                case kCCParamError: return "Illegal parameter value."
                case kCCBufferTooSmall: return "Insufficent buffer provided for specified operation."
                case kCCMemoryFailure: return "Memory allocation failure."
                case kCCAlignmentError: return "Input size was not aligned properly."
                case kCCDecodeError: return "Input data did not decode or decrypt properly."
                case kCCUnimplemented: return "Function not implemented for the current algorithm."
                case kCCInvalidKey: return "Key is not valid."
                default: return "Unknown error status: \(status)"
                }
            case .errorWithMessage(let description): return description
            }
        }
        
        var localizedDescription: String {
            return description
        }
        
        var errorDescription: String? {
            return description
        }
        
        static func verify(_ status: CCCryptorStatus) throws {
            guard status == kCCSuccess else { throw Error.errorWithStatus(status) }
        }
        
        static var invalidSize: Error {
            return Error.errorWithMessage("Invalid size")
        }
        
        static var invalidMode: Error {
            return Error.errorWithMessage("Invalid mode")
        }
    }
}
