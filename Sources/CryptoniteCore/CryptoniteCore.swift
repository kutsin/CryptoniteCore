import Foundation
import DevKit
import ZIPFoundation

public final class CryptoniteCore: NSObject {
    
    private static let shared = CryptoniteCore()
    public static var fileExtension: String {
        return shared.fileExtension
    }
    
    private let queue = DispatchQueue(label: "in.kuts.cryptonite.queue", qos: .userInitiated)
    private let fileExtension = "cryptonite"

    public static func encrypt(using algorithm: Cryptor.Algorithm = .AES256,
                               password: String,
                               hint: String?,
                               sourceURLs: [URL],
                               isMultipleProcessing: Bool,
                               progress: Progress? = nil,
                               completion: @escaping ([URL]?, Swift.Error?) -> Void) {
        shared.queue.async {
            do {
                try shared.clearCryptoniteDirectory()
                if isMultipleProcessing {
                    for sourceURL in sourceURLs {
                        _ = try shared.crypt(using: algorithm,
                                             operation: .encrypt,
                                             password: password,
                                             sourceURLs: [sourceURL],
                                             progress: progress)
                    }
                } else {
                    _ = try shared.crypt(using: algorithm,
                                         operation: .encrypt,
                                         password: password,
                                         sourceURLs: sourceURLs,
                                         progress: progress)
                }
                let fileURLs = try FileManager.default
                    .contentsOfDirectory(atPath: shared.outputDirectoryURL.path)
                    .compactMap { shared.outputDirectoryURL.appendingPathComponent($0) }
                
                if let hint = hint, !hint.isEmpty {
                    try fileURLs.forEach { try shared.append(hint: hint, at: $0) }
                }
                DispatchQueue.main.async {
                    completion(fileURLs, nil)
                }
            } catch {
                DispatchQueue.main.async {
                    completion(nil, error)
                }
            }
        }
    }
    
    public static func decrypt(using algorithm: Cryptor.Algorithm = .AES256,
                               password: String,
                               sourceURLs: [URL],
                               isMultipleProcessing: Bool,
                               progress: Progress? = nil,
                               completion: @escaping ([URL]?, Swift.Error?) -> Void) {
        shared.queue.async {
            do {
                try shared.clearCryptoniteDirectory()
                
                if isMultipleProcessing {
                    for sourceURL in sourceURLs {
                        _ = try shared.crypt(using: algorithm,
                                             operation: .decrypt,
                                             password: password,
                                             sourceURLs: [sourceURL],
                                             progress: progress)
                    }
                } else {
                    _ = try shared.crypt(using: algorithm,
                                         operation: .decrypt,
                                         password: password,
                                         sourceURLs: sourceURLs,
                                         progress: progress)
                }
                
                let fileURLs = try FileManager.default
                    .contentsOfDirectory(atPath: shared.outputDirectoryURL.path)
                    .compactMap { shared.outputDirectoryURL.appendingPathComponent($0) }
                
                DispatchQueue.main.async {
                    completion(fileURLs, nil)
                }
            } catch {
                DispatchQueue.main.async {
                    completion(nil, error)
                }
            }
        }
    }
    
    private func crypt(using algorithm: Cryptor.Algorithm = .AES256,
                       operation: Cryptor.Operation,
                       password: String,
                       sourceURLs: [URL],
                       progress: Progress? = nil) throws {
        
        let saltSize = 32
        let keySize = algorithm.keySize
        let rounds: UInt32 = 10_000
        let ivSize = algorithm.blockSize
        
        let (sourceURL, targetURL) = try prepareURLs(sourceURLs: sourceURLs,
                                                     operation: operation)
        
        guard let inputStream = InputStream(url: sourceURL) else { throw Error.unreadableStream }
        inputStream.open()
        
        guard let outputStream = OutputStream(url: targetURL, append: true) else { throw Error.unwritableStream }
        outputStream.open()
        
        let salt: Data
        let iv: Data
        
        if operation == .encrypt {
            salt = try RandomBytes.generateData(count: saltSize)
            iv = try RandomBytes.generateData(count: ivSize)
            
            let successBuffer = Array<UInt8>(repeating: 0, count: 10)
            let saltBuffer = Array(salt)
            let ivBuffer = Array(iv)
            
            outputStream.write(successBuffer, maxLength: successBuffer.count)
            outputStream.write(saltBuffer, maxLength: saltBuffer.count)
            outputStream.write(ivBuffer, maxLength: ivBuffer.count)
        } else {
            var successBuffer = Array<UInt8>(repeating: 1, count: 10)
            var saltBuffer = Array<UInt8>(repeating:0, count:saltSize)
            var ivBuffer = Array<UInt8>(repeating:0, count:ivSize)

            inputStream.read(&successBuffer, maxLength: successBuffer.count)
            inputStream.read(&saltBuffer, maxLength: saltBuffer.count)
            inputStream.read(&ivBuffer, maxLength: ivBuffer.count)

            salt = Data(saltBuffer)
            iv = Data(ivBuffer)
            
            let success = successBuffer.allSatisfy { $0 == 0 }
            
            guard success else { throw Error.invalidPassword }
        }
        
        let derivedKey = try PBKDF(password: password, salt: salt)
            .process(keyCount: keySize, rounds: rounds)
        
        let cryptor = try Cryptor(operation: operation,
                                  algorithm: algorithm,
                                  options: .init(blockMode: .cbc(iv: iv), padding: .pkcs7),
                                  key: derivedKey)
        
        try process(cryptor: cryptor,
                    inputStream: inputStream,
                    outputStream: outputStream)
        
        if operation == .encrypt {
            let destinationURL = outputDirectoryURL.appendingPathComponent(targetURL.lastPathComponent)
            try FileManager.default.copyItem(at: targetURL, to: destinationURL)
        } else {
            let subprogress = Progress(parent: progress, userInfo: nil)
            try FileManager.default.unzipItem(at: targetURL,
                                              to: outputDirectoryURL,
                                              progress: subprogress)

        }
    }
    
    private func process(cryptor: Cryptor, inputStream: InputStream, outputStream: OutputStream) throws {
        defer {
            inputStream.close()
            outputStream.close()
        }
        
        while true {

            var inputBuffer = Array<UInt8>(repeating:0, count:50_000)
            let bytesRead = inputStream.read(&inputBuffer, maxLength: inputBuffer.count)

            let outputData: Data
            if bytesRead > 0 {
                outputData = try cryptor.process(Data(inputBuffer[0 ..< bytesRead]))
            } else if bytesRead == 0 {
                outputData = try cryptor.finalize()
            } else {
                throw Error.unreadableStream
            }
            
            let outputBuffer = Array(outputData)
            let bytesWritten = outputStream.write(outputBuffer, maxLength: outputBuffer.count)
            if bytesWritten < 0 {
                throw Error.unwritableStream
            }
            
            if bytesRead == 0 {
                return
            }
        }
    }
    
    public static func hintForEncryptedFile(at fileURL: URL) -> String? {
        let handle = try? FileHandle(forReadingFrom: fileURL)
        let data = try? handle?.findData(fromKeyword: "HINT=")
        try? handle?.close_()
        if let data = data {
            return String(data: data, encoding: .utf8)
        }
        return nil
    }
}

extension CryptoniteCore {
    private func prepareURLs(sourceURLs: [URL],
                             operation: Cryptor.Operation,
                             progress: Progress? = nil) throws
    -> (sourceURL: URL, targetURL: URL) {
    
        let inputURL = cryptoniteDirectoryURL.appendingPathComponent("Input")

        try FileManager.default.createDirectory(at: inputURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outputDirectoryURL, withIntermediateDirectories: true)
        try FileManager.default.removeContentsOfDirectory(atPath: inputURL.path)
        
        let sourceURL: URL
        let targetURL: URL
                
        if operation ==  .encrypt {
            let fileName = sourceURLs.count > 1 ?
                "Archive" : sourceURLs[0].deletingPathExtension().lastPathComponent
            
            sourceURL = inputURL.appendingPathComponent(fileName).appendingPathExtension("zip")
            targetURL = inputURL.appendingPathComponent(fileName).appendingPathExtension(fileExtension)
            
            let subprogress = Progress(parent: progress, userInfo: nil)
            try zipItems(at: sourceURLs, to: sourceURL, shouldKeepParent: false, progress: subprogress)
        } else {
            guard sourceURLs.count == 1,
                  sourceURLs[0].pathExtension == fileExtension else { throw Error.invalidFileFormat }
            let fileName = sourceURLs[0].deletingPathExtension().lastPathComponent
            
            sourceURL = inputURL.appendingPathComponent(fileName).appendingPathExtension(fileExtension)
            targetURL = inputURL.appendingPathComponent(fileName).appendingPathExtension("zip")
            
            try FileManager.default.copyItem(at: sourceURLs[0], to: sourceURL)
            try truncateHint(at: sourceURL)
        }
        return (sourceURL, targetURL)
    }
    
    private func zipItems(at sourceURLs: [URL],
                         to destinationURL: URL,
                         shouldKeepParent: Bool = false,
                         progress: Progress? = nil) throws {
    
        let temporaryDirectoryURL = cryptoniteDirectoryURL.appendingPathComponent("com.ZIPFoundation.Temp")
        try FileManager.default.createDirectory(at: temporaryDirectoryURL, withIntermediateDirectories: true)
        try FileManager.default.removeContentsOfDirectory(atPath: temporaryDirectoryURL.path)
        
        for sourceFileURL in sourceURLs {
            let targetFileURL = temporaryDirectoryURL.appendingPathComponent(sourceFileURL.lastPathComponent)
            try FileManager.default.copyItem(at: sourceFileURL, to: targetFileURL)
        }

        try FileManager.default.zipItem(at: temporaryDirectoryURL,
                                        to: destinationURL,
                                        shouldKeepParent: shouldKeepParent,
                                        progress: progress)
        
        try FileManager.default.removeItem(at: temporaryDirectoryURL)
    }
    
    private func append(hint: String, at fileURL: URL) throws {
        guard let data = "HINT=\(hint)".data(using: .utf8) else { throw Error.invalidData }
        let fileHandle = try FileHandle(forUpdating: fileURL)
        try fileHandle.seekToEnd_()
        try fileHandle.write_(contentsOf: data)
        try fileHandle.close_()
    }
    
    private func truncateHint(at fileURL: URL) throws {
        let handle = try FileHandle(forUpdating: fileURL)
        _ = try? handle.truncatedData(fromKeyword: "HINT=")
        try handle.close_()
    }
    
    private func clearCryptoniteDirectory() throws {
        try FileManager.default.removeContentsOfDirectory(atPath: cryptoniteDirectoryURL.path)
    }
    
    private var cryptoniteDirectoryURL: URL {
        return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Cryptonite")
    }
    
    fileprivate var outputDirectoryURL: URL {
        return cryptoniteDirectoryURL.appendingPathComponent("Output")
    }
}

extension CryptoniteCore {
    public enum Error: Swift.Error, LocalizedError {

        case errorWithMessage(String)
        
        var description: String {
            switch self {
            case .errorWithMessage(let description): return description
            }
        }
        
        var localizedDescription: String {
            return description
        }
        
        public var errorDescription: String? {
            return description
        }
        
        static var fileNotExists: Error {
            return Error.errorWithMessage("File not exists")
        }
        
        static var invalidFileFormat: Error {
            return Error.errorWithMessage("Invalid file format")
        }
        
        static var unreadableStream: Error {
            return Error.errorWithMessage("Stream can't read file")
        }
        
        static var unwritableStream: Error {
            return Error.errorWithMessage("Stream can't write file")
        }
        
        static var unavailbaleURL: Error {
            return Error.errorWithMessage("Unavailbale URL")
        }
        
        static var invalidPassword: Error {
            return Error.errorWithMessage("Invalid password")
        }
        
        static var invalidData: Error {
            return Error.errorWithMessage("Invalid data")
        }
    }
}
