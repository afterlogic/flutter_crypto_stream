//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dh/BCDHPrivateKey.java
//

#include "ASN1Encodable.h"
#include "ASN1Encoding.h"
#include "ASN1Integer.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "AlgorithmIdentifier.h"
#include "BCDHPrivateKey.h"
#include "DHDomainParameterSpec.h"
#include "DHParameter.h"
#include "DHParameters.h"
#include "DHPrivateKeyParameters.h"
#include "DHValidationParameters.h"
#include "DomainParameters.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaJceDhDHUtil.h"
#include "PKCS12BagAttributeCarrierImpl.h"
#include "PKCSObjectIdentifiers.h"
#include "PrivateKeyInfo.h"
#include "ValidationParams.h"
#include "X9ObjectIdentifiers.h"
#include "java/io/ObjectInputStream.h"
#include "java/io/ObjectOutputStream.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"
#include "javax/crypto/interfaces/DHPrivateKey.h"
#include "javax/crypto/spec/DHParameterSpec.h"
#include "javax/crypto/spec/DHPrivateKeySpec.h"
#include "javax/security/auth/Destroyable.h"

@interface LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey () {
 @public
  JavaMathBigInteger *x_;
  JavaxCryptoSpecDHParameterSpec *dhSpec_;
  LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info_;
  LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *dhPrivateKey_;
  LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl *attrCarrier_;
}

- (void)readObjectWithJavaIoObjectInputStream:(JavaIoObjectInputStream *)inArg;

- (void)writeObjectWithJavaIoObjectOutputStream:(JavaIoObjectOutputStream *)outArg;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, x_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, dhSpec_, JavaxCryptoSpecDHParameterSpec *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, info_, LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, dhPrivateKey_, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, attrCarrier_, LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl *)

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_readObjectWithJavaIoObjectInputStream_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *self, JavaIoObjectInputStream *inArg);

__attribute__((unused)) static void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_writeObjectWithJavaIoObjectOutputStream_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *self, JavaIoObjectOutputStream *outArg);

@implementation LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey

+ (jlong)serialVersionUID {
  return LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_serialVersionUID;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithJavaxCryptoInterfacesDHPrivateKey:(id<JavaxCryptoInterfacesDHPrivateKey>)key {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithJavaxCryptoInterfacesDHPrivateKey_(self, key);
  return self;
}

- (instancetype)initWithJavaxCryptoSpecDHPrivateKeySpec:(JavaxCryptoSpecDHPrivateKeySpec *)spec {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithJavaxCryptoSpecDHPrivateKeySpec_(self, spec);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)info {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(self, info);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)params {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(self, params);
  return self;
}

- (NSString *)getAlgorithm {
  return @"DH";
}

- (NSString *)getFormat {
  return @"PKCS#8";
}

- (IOSByteArray *)getEncoded {
  @try {
    if (info_ != nil) {
      return [info_ getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
    }
    LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info;
    if ([dhSpec_ isKindOfClass:[LibOrgBouncycastleJcajceSpecDHDomainParameterSpec class]] && [((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) nil_chk(((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) cast_chk(dhSpec_, [LibOrgBouncycastleJcajceSpecDHDomainParameterSpec class])))) getQ] != nil) {
      LibOrgBouncycastleCryptoParamsDHParameters *params = [((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) nil_chk(((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) cast_chk(dhSpec_, [LibOrgBouncycastleJcajceSpecDHDomainParameterSpec class])))) getDomainParameters];
      LibOrgBouncycastleCryptoParamsDHValidationParameters *validationParameters = [((LibOrgBouncycastleCryptoParamsDHParameters *) nil_chk(params)) getValidationParameters];
      LibOrgBouncycastleAsn1X9ValidationParams *vParams = nil;
      if (validationParameters != nil) {
        vParams = new_LibOrgBouncycastleAsn1X9ValidationParams_initWithByteArray_withInt_([validationParameters getSeed], [validationParameters getCounter]);
      }
      info = new_LibOrgBouncycastleAsn1PkcsPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, dhpublicnumber), [new_LibOrgBouncycastleAsn1X9DomainParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1X9ValidationParams_([params getP], [params getG], [params getQ], [params getJ], vParams) toASN1Primitive]), new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_([self getX]));
    }
    else {
      info = new_LibOrgBouncycastleAsn1PkcsPrivateKeyInfo_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, dhKeyAgreement), [new_LibOrgBouncycastleAsn1PkcsDHParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_([((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getG], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getL]) toASN1Primitive]), new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_([self getX]));
    }
    return [info getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
  }
  @catch (JavaLangException *e) {
    return nil;
  }
}

- (NSString *)description {
  return LibOrgBouncycastleJcajceProviderAsymmetricDhJcaJceDhDHUtil_privateKeyToStringWithNSString_withJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(@"DH", x_, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_([((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getG]));
}

- (JavaxCryptoSpecDHParameterSpec *)getParams {
  return dhSpec_;
}

- (JavaMathBigInteger *)getX {
  return x_;
}

- (LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *)engineGetKeyParameters {
  if (dhPrivateKey_ != nil) {
    return dhPrivateKey_;
  }
  if ([dhSpec_ isKindOfClass:[LibOrgBouncycastleJcajceSpecDHDomainParameterSpec class]]) {
    return new_LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(x_, [((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) nil_chk(((LibOrgBouncycastleJcajceSpecDHDomainParameterSpec *) dhSpec_))) getDomainParameters]);
  }
  return new_LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(x_, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_([((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getG], nil, [((JavaxCryptoSpecDHParameterSpec *) nil_chk(dhSpec_)) getL]));
}

- (jboolean)isEqual:(id)o {
  if (!([JavaxCryptoInterfacesDHPrivateKey_class_() isInstance:o])) {
    return false;
  }
  id<JavaxCryptoInterfacesDHPrivateKey> other = (id<JavaxCryptoInterfacesDHPrivateKey>) cast_check(o, JavaxCryptoInterfacesDHPrivateKey_class_());
  return [((JavaMathBigInteger *) nil_chk([self getX])) isEqual:[((id<JavaxCryptoInterfacesDHPrivateKey>) nil_chk(other)) getX]] && [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getG])) isEqual:[((JavaxCryptoSpecDHParameterSpec *) nil_chk([other getParams])) getG]] && [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getP])) isEqual:[((JavaxCryptoSpecDHParameterSpec *) nil_chk([other getParams])) getP]] && [((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getL] == [((JavaxCryptoSpecDHParameterSpec *) nil_chk([other getParams])) getL];
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk([self getX])) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getG])) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk([((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getP])) hash]) ^ [((JavaxCryptoSpecDHParameterSpec *) nil_chk([self getParams])) getL];
}

- (void)setBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                              withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)attribute {
  [((LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl *) nil_chk(attrCarrier_)) setBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:oid withLibOrgBouncycastleAsn1ASN1Encodable:attribute];
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid {
  return [((LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl *) nil_chk(attrCarrier_)) getBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:oid];
}

- (id<JavaUtilEnumeration>)getBagAttributeKeys {
  return [((LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl *) nil_chk(attrCarrier_)) getBagAttributeKeys];
}

- (void)readObjectWithJavaIoObjectInputStream:(JavaIoObjectInputStream *)inArg {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_readObjectWithJavaIoObjectInputStream_(self, inArg);
}

- (void)writeObjectWithJavaIoObjectOutputStream:(JavaIoObjectOutputStream *)outArg {
  LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_writeObjectWithJavaIoObjectOutputStream_(self, outArg);
}

- (void)destroy {
  JavaxSecurityAuthDestroyable_destroy(self);
}

- (jboolean)isDestroyed {
  return JavaxSecurityAuthDestroyable_isDestroyed(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, 3, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 4, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 5, -1, -1, -1, -1, -1 },
    { NULL, "LJavaxCryptoSpecDHParameterSpec;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 8, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 9, 10, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, 11, 12, -1, -1, -1, -1 },
    { NULL, "LJavaUtilEnumeration;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 13, 14, 15, -1, -1, -1 },
    { NULL, "V", 0x2, 16, 17, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithJavaxCryptoInterfacesDHPrivateKey:);
  methods[2].selector = @selector(initWithJavaxCryptoSpecDHPrivateKeySpec:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters:);
  methods[5].selector = @selector(getAlgorithm);
  methods[6].selector = @selector(getFormat);
  methods[7].selector = @selector(getEncoded);
  methods[8].selector = @selector(description);
  methods[9].selector = @selector(getParams);
  methods[10].selector = @selector(getX);
  methods[11].selector = @selector(engineGetKeyParameters);
  methods[12].selector = @selector(isEqual:);
  methods[13].selector = @selector(hash);
  methods[14].selector = @selector(setBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[15].selector = @selector(getBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[16].selector = @selector(getBagAttributeKeys);
  methods[17].selector = @selector(readObjectWithJavaIoObjectInputStream:);
  methods[18].selector = @selector(writeObjectWithJavaIoObjectOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_serialVersionUID, 0x18, -1, -1, -1, -1 },
    { "x_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dhSpec_", "LJavaxCryptoSpecDHParameterSpec;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
    { "info_", "LLibOrgBouncycastleAsn1PkcsPrivateKeyInfo;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
    { "dhPrivateKey_", "LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
    { "attrCarrier_", "LLibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaxCryptoInterfacesDHPrivateKey;", "LJavaxCryptoSpecDHPrivateKeySpec;", "LLibOrgBouncycastleAsn1PkcsPrivateKeyInfo;", "LJavaIoIOException;", "LLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters;", "toString", "equals", "LNSObject;", "hashCode", "setBagAttribute", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Encodable;", "getBagAttribute", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "readObject", "LJavaIoObjectInputStream;", "LJavaIoIOException;LJavaLangClassNotFoundException;", "writeObject", "LJavaIoObjectOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey = { "BCDHPrivateKey", "lib.org.bouncycastle.jcajce.provider.asymmetric.dh", ptrTable, methods, fields, 7, 0x1, 19, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_init(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *self) {
  NSObject_init(self);
  self->attrCarrier_ = new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl_init();
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, init)
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithJavaxCryptoInterfacesDHPrivateKey_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *self, id<JavaxCryptoInterfacesDHPrivateKey> key) {
  NSObject_init(self);
  self->attrCarrier_ = new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl_init();
  self->x_ = [((id<JavaxCryptoInterfacesDHPrivateKey>) nil_chk(key)) getX];
  self->dhSpec_ = [key getParams];
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithJavaxCryptoInterfacesDHPrivateKey_(id<JavaxCryptoInterfacesDHPrivateKey> key) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, initWithJavaxCryptoInterfacesDHPrivateKey_, key)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithJavaxCryptoInterfacesDHPrivateKey_(id<JavaxCryptoInterfacesDHPrivateKey> key) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, initWithJavaxCryptoInterfacesDHPrivateKey_, key)
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithJavaxCryptoSpecDHPrivateKeySpec_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *self, JavaxCryptoSpecDHPrivateKeySpec *spec) {
  NSObject_init(self);
  self->attrCarrier_ = new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl_init();
  self->x_ = [((JavaxCryptoSpecDHPrivateKeySpec *) nil_chk(spec)) getX];
  self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_([spec getP], [spec getG]);
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithJavaxCryptoSpecDHPrivateKeySpec_(JavaxCryptoSpecDHPrivateKeySpec *spec) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, initWithJavaxCryptoSpecDHPrivateKeySpec_, spec)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithJavaxCryptoSpecDHPrivateKeySpec_(JavaxCryptoSpecDHPrivateKeySpec *spec) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, initWithJavaxCryptoSpecDHPrivateKeySpec_, spec)
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *self, LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info) {
  NSObject_init(self);
  self->attrCarrier_ = new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl_init();
  LibOrgBouncycastleAsn1ASN1Sequence *seq = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *) nil_chk(info)) getPrivateKeyAlgorithm])) getParameters]);
  LibOrgBouncycastleAsn1ASN1Integer *derX = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([info parsePrivateKey], [LibOrgBouncycastleAsn1ASN1Integer class]);
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *id_ = [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([info getPrivateKeyAlgorithm])) getAlgorithm];
  self->info_ = info;
  self->x_ = [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(derX)) getValue];
  if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(id_)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, dhKeyAgreement)]) {
    LibOrgBouncycastleAsn1PkcsDHParameter *params = LibOrgBouncycastleAsn1PkcsDHParameter_getInstanceWithId_(seq);
    if ([((LibOrgBouncycastleAsn1PkcsDHParameter *) nil_chk(params)) getL] != nil) {
      self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_([params getP], [params getG], [((JavaMathBigInteger *) nil_chk([params getL])) intValue]);
      self->dhPrivateKey_ = new_LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(self->x_, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_([params getP], [params getG], nil, [((JavaMathBigInteger *) nil_chk([params getL])) intValue]));
    }
    else {
      self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_([params getP], [params getG]);
      self->dhPrivateKey_ = new_LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(self->x_, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_([params getP], [params getG]));
    }
  }
  else if ([id_ isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, dhpublicnumber)]) {
    LibOrgBouncycastleAsn1X9DomainParameters *params = LibOrgBouncycastleAsn1X9DomainParameters_getInstanceWithId_(seq);
    self->dhSpec_ = new_LibOrgBouncycastleJcajceSpecDHDomainParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_([((LibOrgBouncycastleAsn1X9DomainParameters *) nil_chk(params)) getP], [params getQ], [params getG], [params getJ], 0);
    self->dhPrivateKey_ = new_LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHParameters_(self->x_, new_LibOrgBouncycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsDHValidationParameters_([params getP], [params getG], [params getQ], [params getJ], nil));
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$@", @"unknown algorithm type: ", id_));
  }
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_, info)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_, info)
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *self, LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *params) {
  NSObject_init(self);
  self->attrCarrier_ = new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl_init();
  self->x_ = [((LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *) nil_chk(params)) getX];
  self->dhSpec_ = new_LibOrgBouncycastleJcajceSpecDHDomainParameterSpec_initWithLibOrgBouncycastleCryptoParamsDHParameters_([params getParameters]);
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_, params)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_(LibOrgBouncycastleCryptoParamsDHPrivateKeyParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey, initWithLibOrgBouncycastleCryptoParamsDHPrivateKeyParameters_, params)
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_readObjectWithJavaIoObjectInputStream_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *self, JavaIoObjectInputStream *inArg) {
  [((JavaIoObjectInputStream *) nil_chk(inArg)) defaultReadObject];
  self->dhSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_((JavaMathBigInteger *) cast_chk([inArg readObject], [JavaMathBigInteger class]), (JavaMathBigInteger *) cast_chk([inArg readObject], [JavaMathBigInteger class]), [inArg readInt]);
  self->info_ = nil;
  self->attrCarrier_ = new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl_init();
}

void LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey_writeObjectWithJavaIoObjectOutputStream_(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey *self, JavaIoObjectOutputStream *outArg) {
  [((JavaIoObjectOutputStream *) nil_chk(outArg)) defaultWriteObject];
  [outArg writeObjectWithId:[((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getP]];
  [outArg writeObjectWithId:[((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getG]];
  [outArg writeIntWithInt:[((JavaxCryptoSpecDHParameterSpec *) nil_chk(self->dhSpec_)) getL]];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricDhBCDHPrivateKey)