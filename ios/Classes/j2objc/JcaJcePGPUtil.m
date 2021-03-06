//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/JcaJcePGPUtil.java
//

#include "ASN1ObjectIdentifier.h"
#include "BigIntegers.h"
#include "CustomNamedCurves.h"
#include "ECCurve.h"
#include "ECNamedCurveTable.h"
#include "ECPoint.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaJcePGPUtil.h"
#include "PGPException.h"
#include "PGPUtil.h"
#include "X9ECParameters.h"
#include "java/math/BigInteger.h"
#include "javax/crypto/SecretKey.h"
#include "javax/crypto/spec/SecretKeySpec.h"

@implementation LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (id<JavaxCryptoSecretKey>)makeSymmetricKeyWithInt:(jint)algorithm
                                      withByteArray:(IOSByteArray *)keyBytes {
  return LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_makeSymmetricKeyWithInt_withByteArray_(algorithm, keyBytes);
}

+ (LibOrgBouncycastleMathEcECPoint *)decodePointWithJavaMathBigInteger:(JavaMathBigInteger *)encodedPoint
                                   withLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve {
  return LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_decodePointWithJavaMathBigInteger_withLibOrgBouncycastleMathEcECCurve_(encodedPoint, curve);
}

+ (LibOrgBouncycastleAsn1X9X9ECParameters *)getX9ParametersWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)curveOID {
  return LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_getX9ParametersWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(curveOID);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaxCryptoSecretKey;", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x8, 3, 4, 5, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X9X9ECParameters;", 0x8, 6, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(makeSymmetricKeyWithInt:withByteArray:);
  methods[2].selector = @selector(decodePointWithJavaMathBigInteger:withLibOrgBouncycastleMathEcECCurve:);
  methods[3].selector = @selector(getX9ParametersWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "makeSymmetricKey", "I[B", "LLibOrgBouncycastleOpenpgpPGPException;", "decodePoint", "LJavaMathBigInteger;LLibOrgBouncycastleMathEcECCurve;", "LJavaIoIOException;", "getX9Parameters", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil = { "JcaJcePGPUtil", "lib.org.bouncycastle.openpgp.operator.jcajce", ptrTable, methods, NULL, 7, 0x0, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil;
}

@end

void LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_init(LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil *self) {
  NSObject_init(self);
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil, init)
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil, init)
}

id<JavaxCryptoSecretKey> LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_makeSymmetricKeyWithInt_withByteArray_(jint algorithm, IOSByteArray *keyBytes) {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_initialize();
  NSString *algName = LibOrgBouncycastleOpenpgpPGPUtil_getSymmetricCipherNameWithInt_(algorithm);
  if (algName == nil) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(JreStrcat("$I", @"unknown symmetric algorithm: ", algorithm));
  }
  return new_JavaxCryptoSpecSecretKeySpec_initWithByteArray_withNSString_(keyBytes, algName);
}

LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_decodePointWithJavaMathBigInteger_withLibOrgBouncycastleMathEcECCurve_(JavaMathBigInteger *encodedPoint, LibOrgBouncycastleMathEcECCurve *curve) {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_initialize();
  return [((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve)) decodePointWithByteArray:LibOrgBouncycastleUtilBigIntegers_asUnsignedByteArrayWithJavaMathBigInteger_(encodedPoint)];
}

LibOrgBouncycastleAsn1X9X9ECParameters *LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_getX9ParametersWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *curveOID) {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil_initialize();
  LibOrgBouncycastleAsn1X9X9ECParameters *x9Params = LibOrgBouncycastleCryptoEcCustomNamedCurves_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(curveOID);
  if (x9Params == nil) {
    return LibOrgBouncycastleAsn1X9ECNamedCurveTable_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(curveOID);
  }
  return x9Params;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorJcajceJcaJcePGPUtil)
