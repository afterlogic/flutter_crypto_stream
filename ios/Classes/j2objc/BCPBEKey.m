//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/util/BCPBEKey.java
//

#include "ASN1ObjectIdentifier.h"
#include "BCPBEKey.h"
#include "CipherParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "PBE.h"
#include "PBEParametersGenerator.h"
#include "ParametersWithIV.h"
#include "java/security/spec/KeySpec.h"
#include "javax/crypto/spec/PBEKeySpec.h"
#include "javax/security/auth/Destroyable.h"

@implementation LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey

- (instancetype)initWithNSString:(NSString *)algorithm
withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                         withInt:(jint)type
                         withInt:(jint)digest
                         withInt:(jint)keySize
                         withInt:(jint)ivSize
   withJavaxCryptoSpecPBEKeySpec:(JavaxCryptoSpecPBEKeySpec *)pbeKeySpec
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey_initWithNSString_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withInt_withInt_withInt_withInt_withJavaxCryptoSpecPBEKeySpec_withLibOrgBouncycastleCryptoCipherParameters_(self, algorithm, oid, type, digest, keySize, ivSize, pbeKeySpec, param);
  return self;
}

- (instancetype)initWithNSString:(NSString *)algName
     withJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)pbeSpec
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey_initWithNSString_withJavaSecuritySpecKeySpec_withLibOrgBouncycastleCryptoCipherParameters_(self, algName, pbeSpec, param);
  return self;
}

- (NSString *)getAlgorithm {
  return algorithm_;
}

- (NSString *)getFormat {
  return @"RAW";
}

- (IOSByteArray *)getEncoded {
  if (param_ != nil) {
    LibOrgBouncycastleCryptoParamsKeyParameter *kParam;
    if ([param_ isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithIV class]]) {
      kParam = (LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk([((LibOrgBouncycastleCryptoParamsParametersWithIV *) param_) getParameters], [LibOrgBouncycastleCryptoParamsKeyParameter class]);
    }
    else {
      kParam = (LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk(param_, [LibOrgBouncycastleCryptoParamsKeyParameter class]);
    }
    return [((LibOrgBouncycastleCryptoParamsKeyParameter *) nil_chk(kParam)) getKey];
  }
  else {
    if (type_ == LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_PKCS12) {
      return LibOrgBouncycastleCryptoPBEParametersGenerator_PKCS12PasswordToBytesWithCharArray_([((JavaxCryptoSpecPBEKeySpec *) nil_chk(pbeKeySpec_)) getPassword]);
    }
    else if (type_ == LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_PKCS5S2_UTF8) {
      return LibOrgBouncycastleCryptoPBEParametersGenerator_PKCS5PasswordToUTF8BytesWithCharArray_([((JavaxCryptoSpecPBEKeySpec *) nil_chk(pbeKeySpec_)) getPassword]);
    }
    else {
      return LibOrgBouncycastleCryptoPBEParametersGenerator_PKCS5PasswordToBytesWithCharArray_([((JavaxCryptoSpecPBEKeySpec *) nil_chk(pbeKeySpec_)) getPassword]);
    }
  }
}

- (jint)getType {
  return type_;
}

- (jint)getDigest {
  return digest_;
}

- (jint)getKeySize {
  return keySize_;
}

- (jint)getIvSize {
  return ivSize_;
}

- (id<LibOrgBouncycastleCryptoCipherParameters>)getParam {
  return param_;
}

- (IOSCharArray *)getPassword {
  return [((JavaxCryptoSpecPBEKeySpec *) nil_chk(pbeKeySpec_)) getPassword];
}

- (IOSByteArray *)getSalt {
  return [((JavaxCryptoSpecPBEKeySpec *) nil_chk(pbeKeySpec_)) getSalt];
}

- (jint)getIterationCount {
  return [((JavaxCryptoSpecPBEKeySpec *) nil_chk(pbeKeySpec_)) getIterationCount];
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getOID {
  return oid_;
}

- (void)setTryWrongPKCS12ZeroWithBoolean:(jboolean)tryWrong {
  self->tryWrong_ = tryWrong;
}

- (jboolean)shouldTryWrongPKCS12 {
  return tryWrong_;
}

- (void)destroy {
  JavaxSecurityAuthDestroyable_destroy(self);
}

- (jboolean)isDestroyed {
  return JavaxSecurityAuthDestroyable_isDestroyed(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[C", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withInt:withInt:withInt:withInt:withJavaxCryptoSpecPBEKeySpec:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[1].selector = @selector(initWithNSString:withJavaSecuritySpecKeySpec:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAlgorithm);
  methods[3].selector = @selector(getFormat);
  methods[4].selector = @selector(getEncoded);
  methods[5].selector = @selector(getType);
  methods[6].selector = @selector(getDigest);
  methods[7].selector = @selector(getKeySize);
  methods[8].selector = @selector(getIvSize);
  methods[9].selector = @selector(getParam);
  methods[10].selector = @selector(getPassword);
  methods[11].selector = @selector(getSalt);
  methods[12].selector = @selector(getIterationCount);
  methods[13].selector = @selector(getOID);
  methods[14].selector = @selector(setTryWrongPKCS12ZeroWithBoolean:);
  methods[15].selector = @selector(shouldTryWrongPKCS12);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "algorithm_", "LNSString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "oid_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "type_", "I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "digest_", "I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "keySize_", "I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "ivSize_", "I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "param_", "LLibOrgBouncycastleCryptoCipherParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "pbeKeySpec_", "LJavaxCryptoSpecPBEKeySpec;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "tryWrong_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;IIIILJavaxCryptoSpecPBEKeySpec;LLibOrgBouncycastleCryptoCipherParameters;", "LNSString;LJavaSecuritySpecKeySpec;LLibOrgBouncycastleCryptoCipherParameters;", "setTryWrongPKCS12Zero", "Z" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey = { "BCPBEKey", "lib.org.bouncycastle.jcajce.provider.symmetric.util", ptrTable, methods, fields, 7, 0x1, 16, 9, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey;
}

@end

void LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey_initWithNSString_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withInt_withInt_withInt_withInt_withJavaxCryptoSpecPBEKeySpec_withLibOrgBouncycastleCryptoCipherParameters_(LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *self, NSString *algorithm, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, jint type, jint digest, jint keySize, jint ivSize, JavaxCryptoSpecPBEKeySpec *pbeKeySpec, id<LibOrgBouncycastleCryptoCipherParameters> param) {
  NSObject_init(self);
  self->tryWrong_ = false;
  self->algorithm_ = algorithm;
  self->oid_ = oid;
  self->type_ = type;
  self->digest_ = digest;
  self->keySize_ = keySize;
  self->ivSize_ = ivSize;
  self->pbeKeySpec_ = pbeKeySpec;
  self->param_ = param;
}

LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *new_LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey_initWithNSString_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withInt_withInt_withInt_withInt_withJavaxCryptoSpecPBEKeySpec_withLibOrgBouncycastleCryptoCipherParameters_(NSString *algorithm, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, jint type, jint digest, jint keySize, jint ivSize, JavaxCryptoSpecPBEKeySpec *pbeKeySpec, id<LibOrgBouncycastleCryptoCipherParameters> param) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey, initWithNSString_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withInt_withInt_withInt_withInt_withJavaxCryptoSpecPBEKeySpec_withLibOrgBouncycastleCryptoCipherParameters_, algorithm, oid, type, digest, keySize, ivSize, pbeKeySpec, param)
}

LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *create_LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey_initWithNSString_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withInt_withInt_withInt_withInt_withJavaxCryptoSpecPBEKeySpec_withLibOrgBouncycastleCryptoCipherParameters_(NSString *algorithm, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, jint type, jint digest, jint keySize, jint ivSize, JavaxCryptoSpecPBEKeySpec *pbeKeySpec, id<LibOrgBouncycastleCryptoCipherParameters> param) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey, initWithNSString_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withInt_withInt_withInt_withInt_withJavaxCryptoSpecPBEKeySpec_withLibOrgBouncycastleCryptoCipherParameters_, algorithm, oid, type, digest, keySize, ivSize, pbeKeySpec, param)
}

void LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey_initWithNSString_withJavaSecuritySpecKeySpec_withLibOrgBouncycastleCryptoCipherParameters_(LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *self, NSString *algName, id<JavaSecuritySpecKeySpec> pbeSpec, id<LibOrgBouncycastleCryptoCipherParameters> param) {
  NSObject_init(self);
  self->tryWrong_ = false;
  self->algorithm_ = algName;
  self->param_ = param;
}

LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *new_LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey_initWithNSString_withJavaSecuritySpecKeySpec_withLibOrgBouncycastleCryptoCipherParameters_(NSString *algName, id<JavaSecuritySpecKeySpec> pbeSpec, id<LibOrgBouncycastleCryptoCipherParameters> param) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey, initWithNSString_withJavaSecuritySpecKeySpec_withLibOrgBouncycastleCryptoCipherParameters_, algName, pbeSpec, param)
}

LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *create_LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey_initWithNSString_withJavaSecuritySpecKeySpec_withLibOrgBouncycastleCryptoCipherParameters_(NSString *algName, id<JavaSecuritySpecKeySpec> pbeSpec, id<LibOrgBouncycastleCryptoCipherParameters> param) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey, initWithNSString_withJavaSecuritySpecKeySpec_withLibOrgBouncycastleCryptoCipherParameters_, algName, pbeSpec, param)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey)
