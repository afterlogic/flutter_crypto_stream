import Foundation

class KeyPairGeneratorUtil {
    class func createKey(keyData: KeyData, createTime: JavaUtilDate) throws -> LibOrgBouncycastleOpenpgpPGPKeyPair {
         
        var algorithm: jint
        var keyGen: JavaSecurityKeyPairGenerator

            let keyPairGenerator = LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator()
            let rsaKeyPair = generateKeypairWithOpenSSL(generator: keyPairGenerator, strength: keyData.strength)
            return LibOrgBouncycastleOpenpgpOperatorBcBcPGPKeyPair(int: LibOrgBouncycastleBcpgPublicKeyAlgorithmTags.RSA_GENERAL, with: rsaKeyPair, with: createTime)

        return LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair(int: algorithm, with: keyGen.generateKeyPair(), with: createTime)
    }

    private class func generateKeypairWithOpenSSL(generator: LibOrgBouncycastleCryptoGeneratorsCryptoRSAKeyPairGenerator, strength: Int) -> LibOrgBouncycastleCryptoAsymmetricCipherKeyPair? {
        
        let material = OpenSSLHelper.generateKeyMPI(Int32(strength), exponent: 0x10001)
        let bigN = JavaMathBigInteger(nsString: material.nDecString)
        let bigE = JavaMathBigInteger(nsString: material.eDecString)
        let bigD = JavaMathBigInteger(nsString: material.dDecString)
        let bigQ = JavaMathBigInteger(nsString: material.qDecString)
        let bigP = JavaMathBigInteger(nsString: material.pDecString)
        let bigDP = bigP.remainder(with: bigP.subtract(with: JavaMathBigInteger.ONE))
        let bigDQ = bigQ.remainder(with: bigQ.subtract(with: JavaMathBigInteger.ONE))
        let bigQINV = bigQ.modInverse(with: bigP)
        
        let keyParams = LibOrgBouncycastleCryptoParamsRSAKeyParameters(boolean: false, with: bigN, with: bigE)
        let privateCrtKeyParams = LibOrgBouncycastleCryptoParamsRSAPrivateCrtKeyParameters(javaMathBigInteger: bigN, with: bigE, with: bigD, with: bigP, with: bigQ, with: bigDP, with: bigDQ, with: bigQINV)
        
        let keypair = generator.generateKeyPair(with: keyParams, with: privateCrtKeyParams)
        return keypair
    }
    
    private class func getEccParameterSpec(curve: PGPKeyCurve) -> JavaSecuritySpecECGenParameterSpec {
        return JavaSecuritySpecECGenParameterSpec(nsString: curve.parameterSpecName)
    }
}
