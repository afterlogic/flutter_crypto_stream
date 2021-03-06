//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/ECDHCBasicAgreement.java
//

#include "CipherParameters.h"
#include "ECAlgorithms.h"
#include "ECCurve.h"
#include "ECDHCBasicAgreement.h"
#include "ECDomainParameters.h"
#include "ECFieldElement.h"
#include "ECPoint.h"
#include "ECPrivateKeyParameters.h"
#include "ECPublicKeyParameters.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)key {
  self->key_ = (LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) cast_chk(key, [LibOrgBouncycastleCryptoParamsECPrivateKeyParameters class]);
}

- (jint)getFieldSize {
  return ([((LibOrgBouncycastleMathEcECCurve *) nil_chk([((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) nil_chk(key_)) getParameters])) getCurve])) getFieldSize] + 7) / 8;
}

- (JavaMathBigInteger *)calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)pubKey {
  LibOrgBouncycastleCryptoParamsECPublicKeyParameters *pub = (LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) cast_chk(pubKey, [LibOrgBouncycastleCryptoParamsECPublicKeyParameters class]);
  LibOrgBouncycastleCryptoParamsECDomainParameters *params = [((LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) nil_chk(key_)) getParameters];
  if (![((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(params)) isEqual:[((LibOrgBouncycastleCryptoParamsECPublicKeyParameters *) nil_chk(pub)) getParameters]]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"ECDHC public key has wrong domain parameters");
  }
  JavaMathBigInteger *hd = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([params getH])) multiplyWithJavaMathBigInteger:[((LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) nil_chk(key_)) getD]])) modWithJavaMathBigInteger:[params getN]];
  LibOrgBouncycastleMathEcECPoint *pubPoint = LibOrgBouncycastleMathEcECAlgorithms_cleanPointWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_([params getCurve], [pub getQ]);
  if ([((LibOrgBouncycastleMathEcECPoint *) nil_chk(pubPoint)) isInfinity]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Infinity is not a valid public key for ECDHC");
  }
  LibOrgBouncycastleMathEcECPoint *P = [((LibOrgBouncycastleMathEcECPoint *) nil_chk([pubPoint multiplyWithJavaMathBigInteger:hd])) normalize];
  if ([((LibOrgBouncycastleMathEcECPoint *) nil_chk(P)) isInfinity]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Infinity is not a valid agreement value for ECDHC");
  }
  return [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([P getAffineXCoord])) toBigInteger];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, 2, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getFieldSize);
  methods[3].selector = @selector(calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "key_", "LLibOrgBouncycastleCryptoParamsECPrivateKeyParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoCipherParameters;", "calculateAgreement" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement = { "ECDHCBasicAgreement", "lib.org.bouncycastle.crypto.agreement", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement;
}

@end

void LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement_init(LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement *new_LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement, init)
}

LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement *create_LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoAgreementECDHCBasicAgreement)
