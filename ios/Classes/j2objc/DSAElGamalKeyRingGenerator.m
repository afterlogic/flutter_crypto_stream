//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/examples/DSAElGamalKeyRingGenerator.java
//

#include "ArmoredOutputStream.h"
#include "BouncyCastleProvider.h"
#include "DSAElGamalKeyRingGenerator.h"
#include "HashAlgorithmTags.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaPGPContentSignerBuilder.h"
#include "JcaPGPDigestCalculatorProviderBuilder.h"
#include "JcaPGPKeyPair.h"
#include "JcePBESecretKeyEncryptorBuilder.h"
#include "PBESecretKeyEncryptor.h"
#include "PGPDigestCalculator.h"
#include "PGPDigestCalculatorProvider.h"
#include "PGPKeyPair.h"
#include "PGPKeyRingGenerator.h"
#include "PGPPublicKey.h"
#include "PGPPublicKeyRing.h"
#include "PGPSecretKeyRing.h"
#include "PGPSignature.h"
#include "PublicKeyAlgorithmTags.h"
#include "SymmetricKeyAlgorithmTags.h"
#include "java/io/FileOutputStream.h"
#include "java/io/OutputStream.h"
#include "java/io/PrintStream.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "java/security/KeyPair.h"
#include "java/security/KeyPairGenerator.h"
#include "java/security/Security.h"
#include "java/util/Date.h"
#include "javax/crypto/spec/DHParameterSpec.h"

@interface LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator ()

+ (void)exportKeyPairWithJavaIoOutputStream:(JavaIoOutputStream *)secretOut
                     withJavaIoOutputStream:(JavaIoOutputStream *)publicOut
                    withJavaSecurityKeyPair:(JavaSecurityKeyPair *)dsaKp
                    withJavaSecurityKeyPair:(JavaSecurityKeyPair *)elgKp
                               withNSString:(NSString *)identity
                              withCharArray:(IOSCharArray *)passPhrase
                                withBoolean:(jboolean)armor;

@end

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_exportKeyPairWithJavaIoOutputStream_withJavaIoOutputStream_withJavaSecurityKeyPair_withJavaSecurityKeyPair_withNSString_withCharArray_withBoolean_(JavaIoOutputStream *secretOut, JavaIoOutputStream *publicOut, JavaSecurityKeyPair *dsaKp, JavaSecurityKeyPair *elgKp, NSString *identity, IOSCharArray *passPhrase, jboolean armor);

@implementation LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)exportKeyPairWithJavaIoOutputStream:(JavaIoOutputStream *)secretOut
                     withJavaIoOutputStream:(JavaIoOutputStream *)publicOut
                    withJavaSecurityKeyPair:(JavaSecurityKeyPair *)dsaKp
                    withJavaSecurityKeyPair:(JavaSecurityKeyPair *)elgKp
                               withNSString:(NSString *)identity
                              withCharArray:(IOSCharArray *)passPhrase
                                withBoolean:(jboolean)armor {
  LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_exportKeyPairWithJavaIoOutputStream_withJavaIoOutputStream_withJavaSecurityKeyPair_withJavaSecurityKeyPair_withNSString_withCharArray_withBoolean_(secretOut, publicOut, dsaKp, elgKp, identity, passPhrase, armor);
}

+ (void)mainWithNSStringArray:(IOSObjectArray *)args {
  LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_mainWithNSStringArray_(args);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 0, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x9, 3, 4, 5, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(exportKeyPairWithJavaIoOutputStream:withJavaIoOutputStream:withJavaSecurityKeyPair:withJavaSecurityKeyPair:withNSString:withCharArray:withBoolean:);
  methods[2].selector = @selector(mainWithNSStringArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "exportKeyPair", "LJavaIoOutputStream;LJavaIoOutputStream;LJavaSecurityKeyPair;LJavaSecurityKeyPair;LNSString;[CZ", "LJavaIoIOException;LJavaSecurityInvalidKeyException;LJavaSecurityNoSuchProviderException;LJavaSecuritySignatureException;LLibOrgBouncycastleOpenpgpPGPException;", "main", "[LNSString;", "LJavaLangException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator = { "DSAElGamalKeyRingGenerator", "lib.org.bouncycastle.openpgp.examples", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator;
}

@end

void LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_init(LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator *new_LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator, init)
}

LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator *create_LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator, init)
}

void LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_exportKeyPairWithJavaIoOutputStream_withJavaIoOutputStream_withJavaSecurityKeyPair_withJavaSecurityKeyPair_withNSString_withCharArray_withBoolean_(JavaIoOutputStream *secretOut, JavaIoOutputStream *publicOut, JavaSecurityKeyPair *dsaKp, JavaSecurityKeyPair *elgKp, NSString *identity, IOSCharArray *passPhrase, jboolean armor) {
  LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_initialize();
  if (armor) {
    secretOut = new_LibOrgBouncycastleBcpgArmoredOutputStream_initWithJavaIoOutputStream_(secretOut);
  }
  LibOrgBouncycastleOpenpgpPGPKeyPair *dsaKeyPair = new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withJavaSecurityKeyPair_withJavaUtilDate_(LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_DSA, dsaKp, new_JavaUtilDate_init());
  LibOrgBouncycastleOpenpgpPGPKeyPair *elgKeyPair = new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPKeyPair_initWithInt_withJavaSecurityKeyPair_withJavaUtilDate_(LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_ENCRYPT, elgKp, new_JavaUtilDate_init());
  id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator> sha1Calc = [((id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider>) nil_chk([new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_init() build])) getWithInt:LibOrgBouncycastleBcpgHashAlgorithmTags_SHA1];
  LibOrgBouncycastleOpenpgpPGPKeyRingGenerator *keyRingGen = new_LibOrgBouncycastleOpenpgpPGPKeyRingGenerator_initWithInt_withLibOrgBouncycastleOpenpgpPGPKeyPair_withNSString_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector_withLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_withLibOrgBouncycastleOpenpgpOperatorPBESecretKeyEncryptor_(LibOrgBouncycastleOpenpgpPGPSignature_POSITIVE_CERTIFICATION, dsaKeyPair, identity, sha1Calc, nil, nil, new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPContentSignerBuilder_initWithInt_withInt_([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk([dsaKeyPair getPublicKey])) getAlgorithm], LibOrgBouncycastleBcpgHashAlgorithmTags_SHA1), [((LibOrgBouncycastleOpenpgpOperatorJcajceJcePBESecretKeyEncryptorBuilder *) nil_chk([new_LibOrgBouncycastleOpenpgpOperatorJcajceJcePBESecretKeyEncryptorBuilder_initWithInt_withLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator_(LibOrgBouncycastleBcpgSymmetricKeyAlgorithmTags_AES_256, sha1Calc) setProviderWithNSString:@"BC"])) buildWithCharArray:passPhrase]);
  [keyRingGen addSubKeyWithLibOrgBouncycastleOpenpgpPGPKeyPair:elgKeyPair];
  [((LibOrgBouncycastleOpenpgpPGPSecretKeyRing *) nil_chk([keyRingGen generateSecretKeyRing])) encodeWithJavaIoOutputStream:secretOut];
  [((JavaIoOutputStream *) nil_chk(secretOut)) close];
  if (armor) {
    publicOut = new_LibOrgBouncycastleBcpgArmoredOutputStream_initWithJavaIoOutputStream_(publicOut);
  }
  [((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk([keyRingGen generatePublicKeyRing])) encodeWithJavaIoOutputStream:publicOut];
  [((JavaIoOutputStream *) nil_chk(publicOut)) close];
}

void LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_mainWithNSStringArray_(IOSObjectArray *args) {
  LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_initialize();
  JavaSecuritySecurity_addProviderWithJavaSecurityProvider_(new_LibOrgBouncycastleJceProviderBouncyCastleProvider_init());
  if (((IOSObjectArray *) nil_chk(args))->size_ < 2) {
    [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, out))) printlnWithNSString:@"DSAElGamalKeyRingGenerator [-a] identity passPhrase"];
    JavaLangSystem_exitWithInt_(0);
  }
  JavaSecurityKeyPairGenerator *dsaKpg = JavaSecurityKeyPairGenerator_getInstanceWithNSString_withNSString_(@"DSA", @"BC");
  [((JavaSecurityKeyPairGenerator *) nil_chk(dsaKpg)) initialize__WithInt:1024];
  JavaSecurityKeyPair *dsaKp = [dsaKpg generateKeyPair];
  JavaSecurityKeyPairGenerator *elgKpg = JavaSecurityKeyPairGenerator_getInstanceWithNSString_withNSString_(@"ELGAMAL", @"BC");
  JavaMathBigInteger *g = new_JavaMathBigInteger_initWithNSString_withInt_(@"153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
  JavaMathBigInteger *p = new_JavaMathBigInteger_initWithNSString_withInt_(@"9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
  JavaxCryptoSpecDHParameterSpec *elParams = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_(p, g);
  [((JavaSecurityKeyPairGenerator *) nil_chk(elgKpg)) initialize__WithJavaSecuritySpecAlgorithmParameterSpec:elParams];
  JavaSecurityKeyPair *elgKp = [elgKpg generateKeyPair];
  if ([((NSString *) nil_chk(IOSObjectArray_Get(args, 0))) isEqual:@"-a"]) {
    if (args->size_ < 3) {
      [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, out))) printlnWithNSString:@"DSAElGamalKeyRingGenerator [-a] identity passPhrase"];
      JavaLangSystem_exitWithInt_(0);
    }
    JavaIoFileOutputStream *out1 = new_JavaIoFileOutputStream_initWithNSString_(@"secret.asc");
    JavaIoFileOutputStream *out2 = new_JavaIoFileOutputStream_initWithNSString_(@"pub.asc");
    LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_exportKeyPairWithJavaIoOutputStream_withJavaIoOutputStream_withJavaSecurityKeyPair_withJavaSecurityKeyPair_withNSString_withCharArray_withBoolean_(out1, out2, dsaKp, elgKp, IOSObjectArray_Get(args, 1), [((NSString *) nil_chk(IOSObjectArray_Get(args, 2))) java_toCharArray], true);
  }
  else {
    JavaIoFileOutputStream *out1 = new_JavaIoFileOutputStream_initWithNSString_(@"secret.bpg");
    JavaIoFileOutputStream *out2 = new_JavaIoFileOutputStream_initWithNSString_(@"pub.bpg");
    LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator_exportKeyPairWithJavaIoOutputStream_withJavaIoOutputStream_withJavaSecurityKeyPair_withJavaSecurityKeyPair_withNSString_withCharArray_withBoolean_(out1, out2, dsaKp, elgKp, IOSObjectArray_Get(args, 0), [((NSString *) nil_chk(IOSObjectArray_Get(args, 1))) java_toCharArray], false);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpExamplesDSAElGamalKeyRingGenerator)
