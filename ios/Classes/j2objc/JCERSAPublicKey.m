//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/JCERSAPublicKey.java
//

#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "AlgorithmIdentifier.h"
#include "DERNull.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JCERSAPublicKey.h"
#include "JcajceUtilKeyUtil.h"
#include "PKCSObjectIdentifiers.h"
#include "RSAKeyParameters.h"
#include "RSAPublicKey.h"
#include "Strings.h"
#include "SubjectPublicKeyInfo.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/StringBuffer.h"
#include "java/math/BigInteger.h"
#include "java/security/interfaces/RSAPublicKey.h"
#include "java/security/spec/RSAPublicKeySpec.h"

@interface LibOrgBouncycastleJceProviderJCERSAPublicKey () {
 @public
  JavaMathBigInteger *modulus_;
  JavaMathBigInteger *publicExponent_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderJCERSAPublicKey, modulus_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderJCERSAPublicKey, publicExponent_, JavaMathBigInteger *)

@implementation LibOrgBouncycastleJceProviderJCERSAPublicKey

+ (jlong)serialVersionUID {
  return LibOrgBouncycastleJceProviderJCERSAPublicKey_serialVersionUID;
}

- (instancetype)initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:(LibOrgBouncycastleCryptoParamsRSAKeyParameters *)key {
  LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(self, key);
  return self;
}

- (instancetype)initWithJavaSecuritySpecRSAPublicKeySpec:(JavaSecuritySpecRSAPublicKeySpec *)spec {
  LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithJavaSecuritySpecRSAPublicKeySpec_(self, spec);
  return self;
}

- (instancetype)initWithJavaSecurityInterfacesRSAPublicKey:(id<JavaSecurityInterfacesRSAPublicKey>)key {
  LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithJavaSecurityInterfacesRSAPublicKey_(self, key);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)info {
  LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(self, info);
  return self;
}

- (JavaMathBigInteger *)getModulus {
  return modulus_;
}

- (JavaMathBigInteger *)getPublicExponent {
  return publicExponent_;
}

- (NSString *)getAlgorithm {
  return @"RSA";
}

- (NSString *)getFormat {
  return @"X.509";
}

- (IOSByteArray *)getEncoded {
  return LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_getEncodedSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, rsaEncryption), JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE)), new_LibOrgBouncycastleAsn1PkcsRSAPublicKey_initWithJavaMathBigInteger_withJavaMathBigInteger_([self getModulus], [self getPublicExponent]));
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk([self getModulus])) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk([self getPublicExponent])) hash]);
}

- (jboolean)isEqual:(id)o {
  if (o == self) {
    return true;
  }
  if (!([JavaSecurityInterfacesRSAPublicKey_class_() isInstance:o])) {
    return false;
  }
  id<JavaSecurityInterfacesRSAPublicKey> key = (id<JavaSecurityInterfacesRSAPublicKey>) cast_check(o, JavaSecurityInterfacesRSAPublicKey_class_());
  return [((JavaMathBigInteger *) nil_chk([self getModulus])) isEqual:[((id<JavaSecurityInterfacesRSAPublicKey>) nil_chk(key)) getModulus]] && [((JavaMathBigInteger *) nil_chk([self getPublicExponent])) isEqual:[key getPublicExponent]];
}

- (NSString *)description {
  JavaLangStringBuffer *buf = new_JavaLangStringBuffer_init();
  NSString *nl = LibOrgBouncycastleUtilStrings_lineSeparator();
  (void) [((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"RSA Public Key"])) appendWithNSString:nl];
  (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"            modulus: "])) appendWithNSString:[((JavaMathBigInteger *) nil_chk([self getModulus])) toStringWithInt:16]])) appendWithNSString:nl];
  (void) [((JavaLangStringBuffer *) nil_chk([((JavaLangStringBuffer *) nil_chk([buf appendWithNSString:@"    public exponent: "])) appendWithNSString:[((JavaMathBigInteger *) nil_chk([self getPublicExponent])) toStringWithInt:16]])) appendWithNSString:nl];
  return [buf description];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 3, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 4, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 7, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:);
  methods[1].selector = @selector(initWithJavaSecuritySpecRSAPublicKeySpec:);
  methods[2].selector = @selector(initWithJavaSecurityInterfacesRSAPublicKey:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:);
  methods[4].selector = @selector(getModulus);
  methods[5].selector = @selector(getPublicExponent);
  methods[6].selector = @selector(getAlgorithm);
  methods[7].selector = @selector(getFormat);
  methods[8].selector = @selector(getEncoded);
  methods[9].selector = @selector(hash);
  methods[10].selector = @selector(isEqual:);
  methods[11].selector = @selector(description);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = LibOrgBouncycastleJceProviderJCERSAPublicKey_serialVersionUID, 0x18, -1, -1, -1, -1 },
    { "modulus_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicExponent_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoParamsRSAKeyParameters;", "LJavaSecuritySpecRSAPublicKeySpec;", "LJavaSecurityInterfacesRSAPublicKey;", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;", "hashCode", "equals", "LNSObject;", "toString" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceProviderJCERSAPublicKey = { "JCERSAPublicKey", "lib.org.bouncycastle.jce.provider", ptrTable, methods, fields, 7, 0x1, 12, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceProviderJCERSAPublicKey;
}

@end

void LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleJceProviderJCERSAPublicKey *self, LibOrgBouncycastleCryptoParamsRSAKeyParameters *key) {
  NSObject_init(self);
  self->modulus_ = [((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(key)) getModulus];
  self->publicExponent_ = [key getExponent];
}

LibOrgBouncycastleJceProviderJCERSAPublicKey *new_LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleCryptoParamsRSAKeyParameters *key) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderJCERSAPublicKey, initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_, key)
}

LibOrgBouncycastleJceProviderJCERSAPublicKey *create_LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleCryptoParamsRSAKeyParameters *key) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderJCERSAPublicKey, initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_, key)
}

void LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithJavaSecuritySpecRSAPublicKeySpec_(LibOrgBouncycastleJceProviderJCERSAPublicKey *self, JavaSecuritySpecRSAPublicKeySpec *spec) {
  NSObject_init(self);
  self->modulus_ = [((JavaSecuritySpecRSAPublicKeySpec *) nil_chk(spec)) getModulus];
  self->publicExponent_ = [spec getPublicExponent];
}

LibOrgBouncycastleJceProviderJCERSAPublicKey *new_LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithJavaSecuritySpecRSAPublicKeySpec_(JavaSecuritySpecRSAPublicKeySpec *spec) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderJCERSAPublicKey, initWithJavaSecuritySpecRSAPublicKeySpec_, spec)
}

LibOrgBouncycastleJceProviderJCERSAPublicKey *create_LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithJavaSecuritySpecRSAPublicKeySpec_(JavaSecuritySpecRSAPublicKeySpec *spec) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderJCERSAPublicKey, initWithJavaSecuritySpecRSAPublicKeySpec_, spec)
}

void LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithJavaSecurityInterfacesRSAPublicKey_(LibOrgBouncycastleJceProviderJCERSAPublicKey *self, id<JavaSecurityInterfacesRSAPublicKey> key) {
  NSObject_init(self);
  self->modulus_ = [((id<JavaSecurityInterfacesRSAPublicKey>) nil_chk(key)) getModulus];
  self->publicExponent_ = [key getPublicExponent];
}

LibOrgBouncycastleJceProviderJCERSAPublicKey *new_LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithJavaSecurityInterfacesRSAPublicKey_(id<JavaSecurityInterfacesRSAPublicKey> key) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderJCERSAPublicKey, initWithJavaSecurityInterfacesRSAPublicKey_, key)
}

LibOrgBouncycastleJceProviderJCERSAPublicKey *create_LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithJavaSecurityInterfacesRSAPublicKey_(id<JavaSecurityInterfacesRSAPublicKey> key) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderJCERSAPublicKey, initWithJavaSecurityInterfacesRSAPublicKey_, key)
}

void LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleJceProviderJCERSAPublicKey *self, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info) {
  NSObject_init(self);
  @try {
    LibOrgBouncycastleAsn1PkcsRSAPublicKey *pubKey = LibOrgBouncycastleAsn1PkcsRSAPublicKey_getInstanceWithId_([((LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *) nil_chk(info)) parsePublicKey]);
    self->modulus_ = [((LibOrgBouncycastleAsn1PkcsRSAPublicKey *) nil_chk(pubKey)) getModulus];
    self->publicExponent_ = [pubKey getPublicExponent];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid info structure in RSA public key");
  }
}

LibOrgBouncycastleJceProviderJCERSAPublicKey *new_LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderJCERSAPublicKey, initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_, info)
}

LibOrgBouncycastleJceProviderJCERSAPublicKey *create_LibOrgBouncycastleJceProviderJCERSAPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderJCERSAPublicKey, initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_, info)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceProviderJCERSAPublicKey)