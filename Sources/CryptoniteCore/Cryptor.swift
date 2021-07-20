import Foundation
import CommonCrypto.CommonCryptor

public final class Cryptor {
    public let operation: Operation
    public let algorithm: Algorithm
    public let options: Options
    
    private var cryptor: CCCryptorRef?
    
    public init(operation: Operation,
                algorithm: Algorithm,
                options: Options,
                key: Data) throws {
        
        try algorithm.validate(key: key)
        
        self.operation = operation
        self.algorithm = algorithm
        self.options = options
        
        var initializationVector: Data
        if case .cbc(let iv) = options.blockMode, let iv = iv {
            try algorithm.validate(iv: iv)
            initializationVector = iv
        } else {
            let zeroBytes = [UInt8](repeating: 0, count: algorithm.blockSize)
            initializationVector = Data(bytes: zeroBytes, count: algorithm.blockSize)
        }
        
        let status: CCCryptorStatus = key.withUnsafeBytes { keyBuffer in
            initializationVector.withUnsafeBytes { ivBuffer in
                return CCCryptorCreate(operation.rawValue,
                                       algorithm.rawValue,
                                       options.rawValue,
                                       keyBuffer.baseAddress,
                                       key.count,
                                       ivBuffer.baseAddress,
                                       &cryptor)
            }
        }
        
        try Error.verify(status)
    }
    
    deinit {
        guard let cryptor = cryptor else { return }
        let status = CCCryptorRelease(cryptor)
        do { try Error.verify(status) }
        catch { assertionFailure("\(error)") }
    }
    
    @discardableResult
    public func process(_ data: Data) throws -> Data {
        var outLength = Int(0)
        var outBytes = [UInt8](repeating: 0,
                               count: outputLength(for: data.count, final: false))
        let status: CCCryptorStatus = data.withUnsafeBytes {
            CCCryptorUpdate(cryptor,
                            $0.baseAddress,
                            data.count,
                            &outBytes,
                            outBytes.count,
                            &outLength)
        }
        try Error.verify(status)
        return Data(outBytes[..<outLength])
    }
    
    public func finalize() throws -> Data {
        var outLength = Int(0)
        var outBytes = [UInt8](repeating: 0, count: outputLength(for: 0, final: true))
        let status = CCCryptorFinal(cryptor, &outBytes, outBytes.count, &outLength)
        try Error.verify(status)
        return Data(outBytes[..<outLength])
    }
    
    private func outputLength(for inputLength: Int, final: Bool) -> Int {
        return CCCryptorGetOutputLength(cryptor, inputLength, final)
    }
    
    public func reset(iv: Data? = nil) throws {
        var vector = iv
        let status = CCCryptorReset(cryptor, &vector)
        try Error.verify(status)
    }
    
    public static func encrypt(algorithm: Algorithm,
                               options: Options,
                               key: Data,
                               data: Data) throws -> Data {
        return try crypt(.encrypt,
                         algorithm: algorithm,
                         options: options,
                         key: key,
                         data: data)
    }
    
    public static func decrypt(algorithm: Algorithm,
                               options: Options,
                               key: Data,
                               data: Data) throws -> Data {
        return try crypt(.decrypt,
                         algorithm: algorithm,
                         options: options,
                         key: key,
                         data: data)
    }
    
    internal static func crypt(_ operation: Operation,
                               algorithm: Algorithm,
                               options: Options,
                               key: Data,
                               data: Data) throws -> Data {
        try algorithm.validate(key: key)
        
        var outLength = Int(0)
        var outBytes = [UInt8](repeating: 0, count: data.count + algorithm.blockSize)
        
        var initializationVector: Data
        if case .cbc(let cbcIv) = options.blockMode, let iv = cbcIv {
            try algorithm.validate(iv: iv)
            initializationVector = iv
        } else {
            let zeroBytes = [UInt8](repeating: 0, count: algorithm.blockSize)
            initializationVector = Data(bytes: zeroBytes, count: algorithm.blockSize)
        }
        
        let status: CCCryptorStatus = data.withUnsafeBytes { inputBuffer in
            return key.withUnsafeBytes { keyBuffer in
                return initializationVector.withUnsafeBytes { ivBuffer in
                    return CCCrypt(operation.rawValue,
                                   algorithm.rawValue,
                                   options.rawValue,
                                   keyBuffer.baseAddress,
                                   key.count,
                                   ivBuffer.baseAddress,
                                   inputBuffer.baseAddress,
                                   data.count,
                                   &outBytes,
                                   outBytes.count,
                                   &outLength)
                }
            }
        }
        
        try Error.verify(status)
        
        return Data(outBytes[..<outLength])
    }
}
