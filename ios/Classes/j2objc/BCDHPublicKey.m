//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dh/BCDHPublicKey.java
//

#include "ASN1Encodable.h"
#include "ASN1Integer.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "AlgorithmIdentifier.h"
#include "BCDHPublicKey.h"
#include "DHDomainParameterSpec.h"
#include "DHParameter.h"
#include "DHParameters.h"
#include "DHPublicKeyParameters.h"
#include "DHValidationParameters.h"
#include "DomainParameters.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaJceDhDHUtil.h"
#include "JcajceUtilKeyUtil.h"
#include "PKCSObjectIdentifiers.h"
#include "SubjectPublicKeyInfo.h"
#include "ValidationParams.h"
#include "X9ObjectIdentifiers.h"
#include "java/io/IOException.h"
#include "java/io/ObjectInputStream.h"
#include "java/io/ObjectOutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "javax/crypto/interfaces/DHPublicKey.h"
#include "javax/crypto/spec/DHParameterSpec.h"
#include "javax/crypto/spec/DHPublicKeySpec.h"

@interface LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey () {
 @public
  JavaMathBigInteger *y_;
  LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *dhPublicKey_;
  JavaxCryptoSpecDHParameterSpec *dhSpec_;
  LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info_;
}

- (jboolean)isPKCSParamWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (void)readObjectWithJavaIoObjectInputStream:(JavaIoObjectInputStream *)inArg;

- (void)writeObjectWithJavaIoObjectOutputStream:(JavaIoObjectOutputStream *)outArg;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, y_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, dhPublicKey_, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, dhSpec_, JavaxCryptoSpecDHParameterSpec *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, info_, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)

__attribute__((unused)) static jboolean LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_isPKCSParamWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_readObjectWithJavaIoObjectInputStream_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *self, JavaIoObjectInputStream *inArg);

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_writeObjectWithJavaIoObjectOutputStream_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *self, JavaIoObjectOutputStream *outArg);

@implementation LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey

+ (jlong)serialVersionUID {
  return LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_serialVersionUID;
}

- (instancetype)initWithJavaxCryptoSpecDHPublicKeySpec:(JavaxCryptoSpecDHPublicKeySpec *)spec {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaxCryptoSpecDHPublicKeySpec_(self, spec);
  return self;
}

- (instancetype)initWithJavaxCryptoInterfacesDHPublicKey:(id<JavaxCryptoInterfacesDHPublicKey>)key {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaxCryptoInterfacesDHPublicKey_(self, key);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)params {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(self, params);
  return self;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)y
        withJavaxCryptoSpecDHParameterSpec:(JavaxCryptoSpecDHParameterSpec *)dhSpec {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaMathBigInteger_withJavaxCryptoSpecDHParameterSpec_(self, y, dhSpec);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)info {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(self, info);
  return self;
}

- (NSString *)getAlgorithm {
  return @"DH";
}

- (NSString *)getFormat {
  return @"X.509";
}

- (IOSByteArray *)getEncoded {
  if (info_ != nil) {
    return LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_getEncodedSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(info_);
  }
  if ([dhSpec_ isKindOfClass:[LibOrgBouncycastleJcajceSpecDHDomainParameterSpec class]] && [((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) nil_chk(((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) cast_chk(dhSpec_, [LibOrgBouncycastleJcajceSpecDHDomainParameterSpec class])))) getQ] != nil) {
    LibOrgBouncycastleCryptoParamsDHParameters *params = [((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) nil_chk(((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) cast_chk(dhSpec_, [LibOrgBouncycastleJcajceSpecDHDomainParameterSpec class])))) getDomainParameters];
    LibOrgBouncycastleCryptoParamsDHValidationParameters *validationParameters = [((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk(params)) getValidationParameters];
    LibOrgBouncycastleAsn1X9ValidationParams *vParams = nil;
    if (validationParameters != nil) {
      vParams = new_LibOrgBouncycastleAsn1X9ValidationParams_initWithByteArray_withInt_([validationParameters getSeed], [validationParameters getCounter]);
    }
    return LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_getEncodedSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, dhpublicnumber), [new_LibOrgBouncycastleAsn1X9DomainParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1X9ValidationParams_([params getP], [params getG], [params getQ], [params getJ], vParams) toASN1Primitive]), new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(y_));
  }
  return LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_getEncodedSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, dhKeyAgreement), [new_LibOrgBouncycastleAsn1PkcsDHParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_([((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getG], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getL]) toASN1Primitive]), new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(y_));
}

- (NSString *)description {
  return LibOrgBouncycastleJcajceProviderAsymmetricDhJcaJceDhDHUtil_publicKeyToStringWithNSString_withJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(@"DH", y_, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_([((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getG]));
}

- (JavaxCryptoSpecDHParameterSpec *)getParams {
  return dhSpec_;
}

- (JavaMathBigInteger *)getY {
  return y_;
}

- (LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *)engineGetKeyParameters {
  return dhPublicKey_;
}

- (jboolean)isPKCSParamWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  return LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_isPKCSParamWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk([self getY])) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getG])) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getP])) hash]) ^ [((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getL];
}

- (jboolean)isEqual:(id)o {
  if (!([JavaxCryptoInterfacesDHPublicKey_class_() isInstance:o])) {
    return false;
  }
  id<JavaxCryptoInterfacesDHPublicKey> other = (id<JavaxCryptoInterfacesDHPublicKey>) cast_check(o, JavaxCryptoInterfacesDHPublicKey_class_());
  return [((JavaMathBigInteger *) nil_chk([self getY])) isEqual:[((id<JavaxCryptoInterfacesDHPublicKey>) nil_chk(other)) getY]] && [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getG])) isEqual:[((JavaxCryptoSpecDHParameterSpec *) nil_chk([other getParams])) getG]] && [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getP])) isEqual:[((JavaxCryptoSpecDHParameterSpec *) nil_chk([other getParams])) getP]] && [((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getL] == [((JavaxCryptoSpecDHParameterSpec *) nil_chk([other getParams])) getL];
}

- (void)readObjectWithJavaIoObjectInputStream:(JavaIoObjectInputStream *)inArg {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_readObjectWithJavaIoObjectInputStream_(self, inArg);
}

- (void)writeObjectWithJavaIoObjectOutputStream:(JavaIoObjectOutputStream *)outArg {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_writeObjectWithJavaIoObjectOutputStream_(self, outArg);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 5, -1, -1, -1, -1, -1 },
    { NULL, "LJavaxCryptoSpecDHParameterSpec;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 8, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 11, 12, 13, -1, -1, -1 },
    { NULL, "V", 0x2, 14, 15, 16, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaxCryptoSpecDHPublicKeySpec:);
  methods[1].selector = @selector(initWithJavaxCryptoInterfacesDHPublicKey:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters:);
  methods[3].selector = @selector(initWithJavaMathBigInteger:withJavaxCryptoSpecDHParameterSpec:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:);
  methods[5].selector = @selector(getAlgorithm);
  methods[6].selector = @selector(getFormat);
  methods[7].selector = @selector(getEncoded);
  methods[8].selector = @selector(description);
  methods[9].selector = @selector(getParams);
  methods[10].selector = @selector(getY);
  methods[11].selector = @selector(engineGetKeyParameters);
  methods[12].selector = @selector(isPKCSParamWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[13].selector = @selector(hash);
  methods[14].selector = @selector(isEqual:);
  methods[15].selector = @selector(readObjectWithJavaIoObjectInputStream:);
  methods[16].selector = @selector(writeObjectWithJavaIoObjectOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_serialVersionUID, 0x18, -1, -1, -1, -1 },
    { "y_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dhPublicKey_", "LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
    { "dhSpec_", "LJavaxCryptoSpecDHParameterSpec;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
    { "info_", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaxCryptoSpecDHPublicKeySpec;", "LJavaxCryptoInterfacesDHPublicKey;", "LLibOrgBouncycastleCryptoParamsDHPublicKeyParameters;", "LJavaMathBigInteger;LJavaxCryptoSpecDHParameterSpec;", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", "toString", "isPKCSParam", "LLibOrgBouncycastleAsn1ASN1Sequence;", "hashCode", "equals", "LNSObject;", "readObject", "LJavaIoObjectInputStream;", "LJavaIoIOException;LJavaLangClassNotFoundException;", "writeObject", "LJavaIoObjectOutputStream;", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey = { "BCDHPublicKey", "lib.org.bouncycastle.jcajce.provider.asymmetric.dh", ptrTable, methods, fields, 7, 0x1, 17, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaxCryptoSpecDHPublicKeySpec_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *self, JavaxCryptoSpecDHPublicKeySpec *spec) {
  NSObject_init(self);
  self->y_ = [((JavaxCryptoSpecDHPublicKeySpec *) nil_chk(spec)) getY];
  self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_([spec getP], [spec getG]);
  self->dhPublicKey_ = new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(self->y_, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_([spec getP], [spec getG]));
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaxCryptoSpecDHPublicKeySpec_(JavaxCryptoSpecDHPublicKeySpec *spec) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, initWithJavaxCryptoSpecDHPublicKeySpec_, spec)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *create_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaxCryptoSpecDHPublicKeySpec_(JavaxCryptoSpecDHPublicKeySpec *spec) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, initWithJavaxCryptoSpecDHPublicKeySpec_, spec)
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaxCryptoInterfacesDHPublicKey_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *self, id<JavaxCryptoInterfacesDHPublicKey> key) {
  NSObject_init(self);
  self->y_ = [((id<JavaxCryptoInterfacesDHPublicKey>) nil_chk(key)) getY];
  self->dhSpec_ = [key getParams];
  self->dhPublicKey_ = new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(self->y_, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_([((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getG]));
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaxCryptoInterfacesDHPublicKey_(id<JavaxCryptoInterfacesDHPublicKey> key) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, initWithJavaxCryptoInterfacesDHPublicKey_, key)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *create_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaxCryptoInterfacesDHPublicKey_(id<JavaxCryptoInterfacesDHPublicKey> key) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, initWithJavaxCryptoInterfacesDHPublicKey_, key)
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *self, LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *params) {
  NSObject_init(self);
  self->y_ = [((LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *) nil_chk(params)) getY];
  self->dhSpec_ = new_LibOrgBouncycastleJcajceSpecDHDomainParameterSpec_initWithLibOrgBouncycastleCryptoParamsDHParameters_([params getParameters]);
  self->dhPublicKey_ = params;
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_, params)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *create_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_(LibOrgBouncycastleCryptoParamsDHPublicKeyParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, initWithLibOrgBouncycastleCryptoParamsDHPublicKeyParameters_, params)
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaMathBigInteger_withJavaxCryptoSpecDHParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *self, JavaMathBigInteger *y, JavaxCryptoSpecDHParameterSpec *dhSpec) {
  NSObject_init(self);
  self->y_ = y;
  self->dhSpec_ = dhSpec;
  if ([dhSpec isKindOfClass:[LibOrgBouncycastleJcajceSpecDHDomainParameterSpec class]]) {
    self->dhPublicKey_ = new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(y, [((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) nil_chk(((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) dhSpec))) getDomainParameters]);
  }
  else {
    self->dhPublicKey_ = new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(y, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_([((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec)) getP], [dhSpec getG]));
  }
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaMathBigInteger_withJavaxCryptoSpecDHParameterSpec_(JavaMathBigInteger *y, JavaxCryptoSpecDHParameterSpec *dhSpec) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, initWithJavaMathBigInteger_withJavaxCryptoSpecDHParameterSpec_, y, dhSpec)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *create_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithJavaMathBigInteger_withJavaxCryptoSpecDHParameterSpec_(JavaMathBigInteger *y, JavaxCryptoSpecDHParameterSpec *dhSpec) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, initWithJavaMathBigInteger_withJavaxCryptoSpecDHParameterSpec_, y, dhSpec)
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *self, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info) {
  NSObject_init(self);
  self->info_ = info;
  LibOrgBouncycastleAsn1ASN1Integer *derY;
  @try {
    derY = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([((LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *) nil_chk(info)) parsePublicKey], [LibOrgBouncycastleAsn1ASN1Integer class]);
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid info structure in DH public key");
  }
  self->y_ = [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(derY)) getValue];
  LibOrgBouncycastleAsn1ASN1Sequence *seq = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([info getAlgorithm])) getParameters]);
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *id_ = [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([info getAlgorithm])) getAlgorithm];
  if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(id_)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, dhKeyAgreement)] || LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_isPKCSParamWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq)) {
    LibOrgBouncycastleAsn1PkcsDHParameter *params = LibOrgBouncycastleAsn1PkcsDHParameter_getInstanceWithId_(seq);
    if ([((LibOrgBouncycastleAsn1PkcsDHParameter *) nil_chk(params)) getL] != nil) {
      self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_([params getP], [params getG], [((JavaMathBigInteger *) nil_chk([params getL])) intValue]);
    }
    else {
      self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_([params getP], [params getG]);
    }
    self->dhPublicKey_ = new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(self->y_, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_([self->dhSpec_ getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getG]));
  }
  else if ([id_ isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, dhpublicnumber)]) {
    LibOrgBouncycastleAsn1X9DomainParameters *params = LibOrgBouncycastleAsn1X9DomainParameters_getInstanceWithId_(seq);
    LibOrgBouncycastleAsn1X9ValidationParams *validationParams = [((LibOrgBouncycastleAsn1X9DomainParameters *) nil_chk(params)) getValidationParams];
    if (validationParams != nil) {
      self->dhPublicKey_ = new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(self->y_, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHValidationParameters_([params getP], [params getG], [params getQ], [params getJ], new_LibOrgBouncycastleCryptoParamsDHValidationParameters_initWithByteArray_withInt_([validationParams getSeed], [((JavaMathBigInteger *) nil_chk([validationParams getPgenCounter])) intValue])));
    }
    else {
      self->dhPublicKey_ = new_LibOrgBouncycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(self->y_, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHValidationParameters_([params getP], [params getG], [params getQ], [params getJ], nil));
    }
    self->dhSpec_ = new_LibOrgBouncycastleJcajceSpecDHDomainParameterSpec_initWithLibOrgBouncycastleCryptoParamsDHParameters_([self->dhPublicKey_ getParameters]);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"unknown algorithm type: ", id_));
  }
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_, info)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *create_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey, initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_, info)
}

jboolean LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_isPKCSParamWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] == 2) {
    return true;
  }
  if ([seq size] > 3) {
    return false;
  }
  LibOrgBouncycastleAsn1ASN1Integer *l = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:2]);
  LibOrgBouncycastleAsn1ASN1Integer *p = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:0]);
  if ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(l)) getValue])) compareToWithId:JavaMathBigInteger_valueOfWithLong_([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(p)) getValue])) bitLength])] > 0) {
    return false;
  }
  return true;
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_readObjectWithJavaIoObjectInputStream_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *self, JavaIoObjectInputStream *inArg) {
  [((JavaIoObjectInputStream *) nil_chk(inArg)) defaultReadObject];
  self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_((JavaMathBigInteger *) cast_chk([inArg readObject], [JavaMathBigInteger class]), (JavaMathBigInteger *) cast_chk([inArg readObject], [JavaMathBigInteger class]), [inArg readInt]);
  self->info_ = nil;
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey_writeObjectWithJavaIoObjectOutputStream_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey *self, JavaIoObjectOutputStream *outArg) {
  [((JavaIoObjectOutputStream *) nil_chk(outArg)) defaultWriteObject];
  [outArg writeObjectWithId:[((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getP]];
  [outArg writeObjectWithId:[((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getG]];
  [outArg writeIntWithInt:[((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getL]];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPublicKey)
