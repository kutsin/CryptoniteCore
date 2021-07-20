import Foundation
import CommonCrypto.CommonCryptor

extension Cryptor {
    public struct Options {
        public enum BlockMode: Equatable {
            case cbc(iv: Data?)
            case ecb
        }
        
        public enum Padding {
            case pkcs7
            case noPadding
        }
        
        public let blockMode: BlockMode
        public let padding: Padding
        
        public var iv: Data? {
            switch blockMode {
            case .cbc(let iv): return iv
            case .ecb: return nil
            }
        }
        
        public init(blockMode: BlockMode,
                    padding: Padding = .pkcs7) {
            self.blockMode = blockMode
            self.padding = padding
        }
        
        internal var rawValue: CCOptions {
            var options: CCOptions = 0
            switch blockMode {
            case .ecb: options |= CCOptions(kCCOptionECBMode)
            case .cbc: break
            }
            
            switch padding {
            case .pkcs7: options |= CCOptions(kCCOptionPKCS7Padding)
            case .noPadding: break
            }
            return options
        }
    }
}
