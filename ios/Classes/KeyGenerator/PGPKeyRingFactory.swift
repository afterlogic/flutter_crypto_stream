import Foundation

public class PGPKeyRingFactory {

    let keyRingGenerator: LibOrgBouncycastleOpenpgpPGPKeyRingGenerator

    public var publicKeyRing: LibOrgBouncycastleOpenpgpPGPPublicKeyRing {
        return keyRingGenerator.generatePublicKeyRing()
    }

    public var secretKeyRing: LibOrgBouncycastleOpenpgpPGPSecretKeyRing {
        return keyRingGenerator.generateSecretKeyRing()
    }

    public init(generateKeyData: GenerateKeyData) throws {
        self.keyRingGenerator = PGPKeyRingFactory.keyRingGenerator(generateKeyData: generateKeyData)!
    }

}

extension PGPKeyRingFactory {

    public static func keyRingGenerator(generateKeyData: GenerateKeyData) -> LibOrgBouncycastleOpenpgpPGPKeyRingGenerator? {
        do {
            let userID =  generateKeyData.email
            let date = JavaUtilDate()
            let masterKey = try KeyPairGeneratorUtil.createKey(keyData: generateKeyData.masterKey, createTime: date)
            let subkey = try KeyPairGeneratorUtil.createKey(keyData: generateKeyData.subkey, createTime: date)
            let masterSignatureSubpacketGenerator: LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator = {
                let signatureSubpacketGenerator = LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator()
                
                signatureSubpacketGenerator.setKeyFlagsWithBoolean(false, with: LibOrgBouncycastleBcpgSigKeyFlags.SIGN_DATA | LibOrgBouncycastleBcpgSigKeyFlags.CERTIFY_OTHER)
                signatureSubpacketGenerator.setPreferredSymmetricAlgorithmsWithBoolean(false, with: IOSIntArray(ints: [
                    LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags.AES_256,
                    LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags.AES_192,
                    LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags.AES_128,
                    ], count: 3))
                signatureSubpacketGenerator.setPreferredHashAlgorithmsWithBoolean(false, with: IOSIntArray(ints: [
                    LibOrgBouncycastleBcpgHashAlgorithmTags.SHA256,
                    LibOrgBouncycastleBcpgHashAlgorithmTags.SHA1,
                    LibOrgBouncycastleBcpgHashAlgorithmTags.SHA384,
                    LibOrgBouncycastleBcpgHashAlgorithmTags.SHA512,
                    LibOrgBouncycastleBcpgHashAlgorithmTags.SHA224,
                    ], count: 5))
                signatureSubpacketGenerator.setFeatureWithBoolean(false, withByte: LibOrgBouncycastleBcpgSigFeatures.FEATURE_MODIFICATION_DETECTION)
                
                return signatureSubpacketGenerator
            }()
            
            let subSignatureSubpacketGenerator: LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator = {
                let signatureSubpacketGenerator = LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator()
                signatureSubpacketGenerator.setKeyFlagsWithBoolean(false, with: LibOrgBouncycastleBcpgSigKeyFlags.ENCRYPT_COMMS | LibOrgBouncycastleBcpgSigKeyFlags.ENCRYPT_STORAGE)
                return signatureSubpacketGenerator
            }()
            
            let sha1Calculator = LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder().build()?.getWith(LibOrgBouncycastleBcpgHashAlgorithmTags.SHA1)
            let sha256Calculator = LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder().build()?.getWith(LibOrgBouncycastleBcpgHashAlgorithmTags.SHA256)
            
            guard let encryptor = LibOrgBouncycastleOpenpgpOperatorJcajceJcePBESecretKeyEncryptorBuilder(int: LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags.AES_256, with: sha256Calculator, with: 0x90)
                .setProviderWith(LibOrgBouncycastleJceProviderBouncyCastleProvider.PROVIDER_NAME)
                .build(with: IOSCharArray(nsString: generateKeyData.password)) else {
                    assertionFailure()
                    return nil
            }
            
            guard let algorithm = masterKey.getPublicKey()?.getAlgorithm() else {
                assertionFailure()
                return nil
            }
            
            let keyRingGenerator =  LibOrgBouncycastleOpenpgpPGPKeyRingGenerator(int: LibOrgBouncycastleOpenpgpPGPSignature.POSITIVE_CERTIFICATION,
                                                                 with: masterKey,
                                                                 with: userID,
                                                                 with: sha1Calculator,
                                                                 with: masterSignatureSubpacketGenerator.generate(),
                                                                 with: nil,
                                                                 with: LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentSignerBuilder(int: algorithm, with: LibOrgBouncycastleBcpgHashAlgorithmTags.SHA512).setProviderWith(LibOrgBouncycastleJceProviderBouncyCastleProvider.PROVIDER_NAME),
                                                                 with: encryptor)
            keyRingGenerator.addSubKey(with: subkey, with: subSignatureSubpacketGenerator.generate(), with: nil)
            return keyRingGenerator
        } catch let error {
            NSLog("%error: @", error.localizedDescription)
            return nil
        }
        
    }
}
