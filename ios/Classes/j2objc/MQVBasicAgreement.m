//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/MQVBasicAgreement.java
//

#include "CipherParameters.h"
#include "DHMQVPrivateParameters.h"
#include "DHMQVPublicParameters.h"
#include "DHParameters.h"
#include "DHPrivateKeyParameters.h"
#include "DHPublicKeyParameters.h"
#include "J2ObjC_source.h"
#include "MQVBasicAgreement.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoAgreementMQVBasicAgreement ()

- (JavaMathBigInteger *)calculateDHMQVAgreementWithLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)parameters
                                     withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)xA
                                      withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)yB
                                     withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)rA
                                      withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)tA
                                      withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)tB;

@end

inline JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_get_ONE(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementMQVBasicAgreement, ONE, JavaMathBigInteger *)

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_calculateDHMQVAgreementWithLibOrgBouncycastleCryptoParamsDHParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoAgreementMQVBasicAgreement *self, LibOrgBouncycastleCryptoParamsDHParameters *parameters, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *xA, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *yB, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *rA, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *tA, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *tB);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoAgreementMQVBasicAgreement)

@implementation LibOrgBouncycastleCryptoAgreementMQVBasicAgreement

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)key {
  self->privParams_ = (LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *) cast_chk(key, [LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters class]);
}

- (jint)getFieldSize {
  return ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *) nil_chk(privParams_)) getStaticPrivateKey])) getParameters])) getP])) bitLength] + 7) / 8;
}

- (JavaMathBigInteger *)calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)pubKey {
  LibOrgBouncycastleCryptoParamsDHMQVPublicParameters *pubParams = (LibOrgBouncycastleCryptoParamsDHMQVPublicParameters *) cast_chk(pubKey, [LibOrgBouncycastleCryptoParamsDHMQVPublicParameters class]);
  LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *staticPrivateKey = [((LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *) nil_chk(privParams_)) getStaticPrivateKey];
  if (![((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *) nil_chk(privParams_)) getStaticPrivateKey])) getParameters])) isEqual:[((LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsDHMQVPublicParameters *) nil_chk(pubParams)) getStaticPublicKey])) getParameters]]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"MQV public key components have wrong domain parameters");
  }
  if ([((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *) nil_chk([((LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *) nil_chk(privParams_)) getStaticPrivateKey])) getParameters])) getQ] == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"MQV key domain parameters do not have Q set");
  }
  JavaMathBigInteger *agreement = LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_calculateDHMQVAgreementWithLibOrgBouncycastleCryptoParamsDHParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(self, [((LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *) nil_chk(staticPrivateKey)) getParameters], staticPrivateKey, [pubParams getStaticPublicKey], [((LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *) nil_chk(privParams_)) getEphemeralPrivateKey], [((LibOrgBouncycastleCryptoParamsDHMQVPrivateParameters *) nil_chk(privParams_)) getEphemeralPublicKey], [pubParams getEphemeralPublicKey]);
  if ([((JavaMathBigInteger *) nil_chk(agreement)) isEqual:LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_ONE]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"1 is not a valid agreement value for MQV");
  }
  return agreement;
}

- (JavaMathBigInteger *)calculateDHMQVAgreementWithLibOrgBouncycastleCryptoParamsDHParameters:(LibOrgBouncycastleCryptoParamsDHParameters *)parameters
                                     withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)xA
                                      withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)yB
                                     withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)rA
                                      withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)tA
                                      withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)tB {
  return LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_calculateDHMQVAgreementWithLibOrgBouncycastleCryptoParamsDHParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(self, parameters, xA, yB, rA, tA, tB);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, 2, 1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getFieldSize);
  methods[3].selector = @selector(calculateAgreementWithLibOrgBouncycastleCryptoCipherParameters:);
  methods[4].selector = @selector(calculateDHMQVAgreementWithLibOrgBouncycastleCryptoParamsDHParameters:withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 5, -1, -1 },
    { "privParams_", "LLibOrgBouncycastleCryptoParamsDHMQVPrivateParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoCipherParameters;", "calculateAgreement", "calculateDHMQVAgreement", "LLibOrgBouncycastleCryptoParamsDHParameters;LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;", &LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_ONE };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoAgreementMQVBasicAgreement = { "MQVBasicAgreement", "lib.org.bouncycastle.crypto.agreement", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoAgreementMQVBasicAgreement;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoAgreementMQVBasicAgreement class]) {
    LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoAgreementMQVBasicAgreement)
  }
}

@end

void LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_init(LibOrgBouncycastleCryptoAgreementMQVBasicAgreement *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoAgreementMQVBasicAgreement *new_LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoAgreementMQVBasicAgreement, init)
}

LibOrgBouncycastleCryptoAgreementMQVBasicAgreement *create_LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoAgreementMQVBasicAgreement, init)
}

JavaMathBigInteger *LibOrgBouncycastleCryptoAgreementMQVBasicAgreement_calculateDHMQVAgreementWithLibOrgBouncycastleCryptoParamsDHParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_withLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoAgreementMQVBasicAgreement *self, LibOrgBouncycastleCryptoParamsDHParameters *parameters, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *xA, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *yB, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *rA, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *tA, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *tB) {
  JavaMathBigInteger *q = [((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk(parameters)) getQ];
  jint w = ([((JavaMathBigInteger *) nil_chk(q)) bitLength] + 1) / 2;
  JavaMathBigInteger *twoW = [((JavaMathBigInteger *) nil_chk(JavaMathBigInteger_valueOfWithLong_(2))) powWithInt:w];
  JavaMathBigInteger *TA = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *) nil_chk(tA)) getY])) modWithJavaMathBigInteger:twoW])) addWithJavaMathBigInteger:twoW];
  JavaMathBigInteger *SA = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *) nil_chk(rA)) getX])) addWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(TA)) multiplyWithJavaMathBigInteger:[((LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *) nil_chk(xA)) getX]]])) modWithJavaMathBigInteger:q];
  JavaMathBigInteger *TB = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *) nil_chk(tB)) getY])) modWithJavaMathBigInteger:twoW])) addWithJavaMathBigInteger:twoW];
  JavaMathBigInteger *Z = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([tB getY])) multiplyWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *) nil_chk(yB)) getY])) modPowWithJavaMathBigInteger:TB withJavaMathBigInteger:[parameters getP]]])) modPowWithJavaMathBigInteger:SA withJavaMathBigInteger:[parameters getP]];
  return Z;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoAgreementMQVBasicAgreement)
