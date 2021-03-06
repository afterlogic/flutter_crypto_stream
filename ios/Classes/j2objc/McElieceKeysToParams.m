//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/mceliece/McElieceKeysToParams.java
//

#include "AsymmetricKeyParameter.h"
#include "BCMcEliecePrivateKey.h"
#include "BCMcEliecePublicKey.h"
#include "GF2Matrix.h"
#include "GF2mField.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "McElieceKeysToParams.h"
#include "McEliecePrivateKeyParameters.h"
#include "Permutation.h"
#include "PolynomialGF2mSmallM.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"

@implementation LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePublicKeyParameterWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key {
  return LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams_generatePublicKeyParameterWithJavaSecurityPublicKey_(key);
}

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePrivateKeyParameterWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key {
  return LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams_generatePrivateKeyParameterWithJavaSecurityPrivateKey_(key);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x9, 3, 4, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generatePublicKeyParameterWithJavaSecurityPublicKey:);
  methods[2].selector = @selector(generatePrivateKeyParameterWithJavaSecurityPrivateKey:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "generatePublicKeyParameter", "LJavaSecurityPublicKey;", "LJavaSecurityInvalidKeyException;", "generatePrivateKeyParameter", "LJavaSecurityPrivateKey;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams = { "McElieceKeysToParams", "lib.org.bouncycastle.pqc.jcajce.provider.mceliece", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams;
}

@end

void LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams_init(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams *new_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams, init)
}

LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams *create_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams, init)
}

LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams_generatePublicKeyParameterWithJavaSecurityPublicKey_(id<JavaSecurityPublicKey> key) {
  LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams_initialize();
  if ([key isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePublicKey class]]) {
    LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePublicKey *k = (LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePublicKey *) key;
    return [((LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePublicKey *) nil_chk(k)) getKeyParams];
  }
  @throw new_JavaSecurityInvalidKeyException_initWithNSString_(JreStrcat("$$", @"can't identify McEliece public key: ", [[((id<JavaSecurityPublicKey>) nil_chk(key)) java_getClass] getName]));
}

LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams_generatePrivateKeyParameterWithJavaSecurityPrivateKey_(id<JavaSecurityPrivateKey> key) {
  LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams_initialize();
  if ([key isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePrivateKey class]]) {
    LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePrivateKey *k = (LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePrivateKey *) key;
    return new_LibOrgBouncycastlePqcCryptoMcelieceMcEliecePrivateKeyParameters_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2mField_withLibOrgBouncycastlePqcMathLinearalgebraPolynomialGF2mSmallM_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraPermutation_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_([((LibOrgBouncycastlePqcJcajceProviderMcelieceBCMcEliecePrivateKey *) nil_chk(k)) getN], [k getK], [k getField], [k getGoppaPoly], [k getP1], [k getP2], [k getSInv]);
  }
  @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"can't identify McEliece private key.");
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceKeysToParams)
