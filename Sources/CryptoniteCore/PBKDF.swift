import Foundation
import CommonCrypto.CommonKeyDerivation

public struct PBKDF {
    
    public enum PseudoRandomAlgorithm {
        case SHA1
        case SHA224
        case SHA256
        case SHA384
        case SHA512
        
        var rawValue: CCPBKDFAlgorithm {
            switch self {
            case .SHA1: return CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1)
            case .SHA224: return CCPBKDFAlgorithm(kCCPRFHmacAlgSHA224)
            case .SHA256: return CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256)
            case .SHA384: return CCPBKDFAlgorithm(kCCPRFHmacAlgSHA384)
            case .SHA512: return CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512)
            }
        }
    }
    
    private let password: String
    private let salt: Data
    
    public init(password: String, salt: Data) {
        self.password = password
        self.salt = salt
    }
    
    func process(algorithm: PseudoRandomAlgorithm = .SHA512,
                 keyCount: Int,
                 rounds: UInt32) throws -> Data {
        var derivedKey = [UInt8](repeating: 0, count: keyCount)
        let status: CCStatus = salt.withUnsafeBytes { saltBuffer in
            return CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                        password,
                                        password.utf8.count,
                                        saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                                        salt.count,
                                        algorithm.rawValue,
                                        rounds,
                                        &derivedKey,
                                        derivedKey.count)
        }
        try Cryptor.Error.verify(status)
        return Data(derivedKey)
    }
    
    public func calibrate(algorithm: PseudoRandomAlgorithm,
                          keyCount: Int,
                          milliseconds: UInt32) -> UInt32 {
        return CCCalibratePBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            password.utf8.count,
            salt.count,
            algorithm.rawValue,
            keyCount,
            milliseconds)
    }
}
