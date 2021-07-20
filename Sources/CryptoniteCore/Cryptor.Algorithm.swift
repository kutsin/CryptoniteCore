import Foundation
import CommonCrypto.CommonCryptor

extension Cryptor {
    public enum Algorithm {
        case AES128
        case AES192
        case AES256
        case DES
        case TripleDES
        case CAST(keySize: Int)
        case RC4(keySize: Int)
        case RC2(keySize: Int)
        case Blowfish(keySize: Int)
        
        var rawValue: CCAlgorithm {
            switch self {
            case .AES128,
                 .AES192,
                 .AES256: return CCAlgorithm(kCCAlgorithmAES)
            case .DES: return CCAlgorithm(kCCAlgorithmDES)
            case .TripleDES: return CCAlgorithm(kCCAlgorithm3DES)
            case .CAST: return CCAlgorithm(kCCAlgorithmCAST)
            case .RC4: return CCAlgorithm(kCCAlgorithmRC4)
            case .RC2: return CCAlgorithm(kCCAlgorithmRC2)
            case .Blowfish: return CCAlgorithm(kCCAlgorithmBlowfish)
            }
        }
        
        public var blockSize: Int {
            switch self {
            case .AES128, .AES192, .AES256: return kCCBlockSizeAES128
            case .DES: return kCCBlockSizeDES
            case .TripleDES: return kCCBlockSize3DES
            case .CAST: return kCCBlockSizeCAST
            case .RC4, .RC2: return kCCBlockSizeRC2
            case .Blowfish: return kCCBlockSizeBlowfish
            }
        }
        
        public var keySize: Int {
            switch self {
            case .AES128: return kCCKeySizeAES128
            case .AES192: return kCCKeySizeAES192
            case .AES256: return kCCKeySizeAES256
            case .DES: return kCCKeySizeDES
            case .TripleDES: return kCCKeySize3DES
            case .CAST(let keySize),
                 .RC4(let keySize),
                 .RC2(let keySize),
                 .Blowfish(let keySize): return keySize
            }
        }
        
        private var validKeySizeRange: ClosedRange<Int> {
            switch self {
            case .CAST: return kCCKeySizeMinCAST ... kCCKeySizeMaxCAST
            case .RC4: return kCCKeySizeMinRC4 ... kCCKeySizeMaxRC4
            case .RC2: return kCCKeySizeMinRC2 ... kCCKeySizeMaxRC2
            case .Blowfish: return kCCKeySizeMinBlowfish ... kCCKeySizeMaxBlowfish
            default: return keySize ... keySize
            }
        }
        
        func validate(key: Data) throws {
            guard validKeySizeRange.contains(key.count) else {
                throw Error.invalidSize
            }
        }
        
        func validate(iv: Data) throws {
            guard iv.count == blockSize else {
                throw Error.invalidSize
            }
        }
    }
}
