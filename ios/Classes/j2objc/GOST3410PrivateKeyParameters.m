//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/GOST3410PrivateKeyParameters.java
//

#include "GOST3410KeyParameters.h"
#include "GOST3410Parameters.h"
#include "GOST3410PrivateKeyParameters.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters () {
 @public
  JavaMathBigInteger *x_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters, x_, JavaMathBigInteger *)

@implementation LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)x
withLibOrgBouncycastleCryptoParamsGOST3410Parameters:(LibOrgBouncycastleCryptoParamsGOST3410Parameters *)params {
  LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(self, x, params);
  return self;
}

- (JavaMathBigInteger *)getX {
  return x_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:withLibOrgBouncycastleCryptoParamsGOST3410Parameters:);
  methods[1].selector = @selector(getX);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "x_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;LLibOrgBouncycastleCryptoParamsGOST3410Parameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters = { "GOST3410PrivateKeyParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters;
}

@end

void LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters *self, JavaMathBigInteger *x, LibOrgBouncycastleCryptoParamsGOST3410Parameters *params) {
  LibOrgBouncycastleCryptoParamsGOST3410KeyParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(self, true, params);
  self->x_ = x;
}

LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(JavaMathBigInteger *x, LibOrgBouncycastleCryptoParamsGOST3410Parameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters, initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_, x, params)
}

LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_(JavaMathBigInteger *x, LibOrgBouncycastleCryptoParamsGOST3410Parameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters, initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_, x, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters)
