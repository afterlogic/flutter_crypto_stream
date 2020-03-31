import Foundation

public struct KeyData {
    public var strength: Int = 3072
    public var curve: PGPKeyCurve?

    public init(strength: Int = 3072, curve: PGPKeyCurve? = nil) {
        self.strength = strength
        self.curve = curve
    }
}

public struct GenerateKeyData {
    public var email: String
    public var password: String
    public var masterKey: KeyData
    public var subkey: KeyData

    public init(email: String, password: String?, masterKey: KeyData, subkey: KeyData) {
        self.email = email
        self.password = password ?? ""
        self.masterKey = masterKey
        self.subkey = subkey
    }
}

public enum PGPKeyCurve {
    case NIST_P256
    case NIST_P384
    case NIST_P521
    case Secp256k1
    
    public var parameterSpecName: String {
        switch self {
        case .NIST_P256:
            return "P-256"
        case .NIST_P384:
            return "P-384"
        case .NIST_P521:
            return "P-521"
        case .Secp256k1:
            return "secp256k1"
        }
    }
}
