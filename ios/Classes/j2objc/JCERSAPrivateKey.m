//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/JCERSAPrivateKey.java
//

#include "ASN1Encodable.h"
#include "ASN1ObjectIdentifier.h"
#include "AlgorithmIdentifier.h"
#include "DERNull.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JCERSAPrivateKey.h"
#include "JcajceUtilKeyUtil.h"
#include "PKCS12BagAttributeCarrierImpl.h"
#include "PKCSObjectIdentifiers.h"
#include "RSAKeyParameters.h"
#include "RSAPrivateKey.h"
#include "java/io/ObjectInputStream.h"
#include "java/io/ObjectOutputStream.h"
#include "java/math/BigInteger.h"
#include "java/security/interfaces/RSAPrivateKey.h"
#include "java/security/spec/RSAPrivateKeySpec.h"
#include "java/util/Enumeration.h"
#include "javax/security/auth/Destroyable.h"

@interface LibOrgBouncycastleJceProviderJCERSAPrivateKey () {
 @public
  LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl *attrCarrier_;
}

- (void)readObjectWithJavaIoObjectInputStream:(JavaIoObjectInputStream *)inArg;

- (void)writeObjectWithJavaIoObjectOutputStream:(JavaIoObjectOutputStream *)outArg;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceProviderJCERSAPrivateKey, attrCarrier_, LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl *)

inline JavaMathBigInteger *LibOrgBouncycastleJceProviderJCERSAPrivateKey_get_ZERO(void);
inline JavaMathBigInteger *LibOrgBouncycastleJceProviderJCERSAPrivateKey_set_ZERO(JavaMathBigInteger *value);
static JavaMathBigInteger *LibOrgBouncycastleJceProviderJCERSAPrivateKey_ZERO;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleJceProviderJCERSAPrivateKey, ZERO, JavaMathBigInteger *)

__attribute__((unused)) static void LibOrgBouncycastleJceProviderJCERSAPrivateKey_readObjectWithJavaIoObjectInputStream_(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self, JavaIoObjectInputStream *inArg);

__attribute__((unused)) static void LibOrgBouncycastleJceProviderJCERSAPrivateKey_writeObjectWithJavaIoObjectOutputStream_(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self, JavaIoObjectOutputStream *outArg);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJceProviderJCERSAPrivateKey)

@implementation LibOrgBouncycastleJceProviderJCERSAPrivateKey

+ (jlong)serialVersionUID {
  return LibOrgBouncycastleJceProviderJCERSAPrivateKey_serialVersionUID;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJceProviderJCERSAPrivateKey_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:(LibOrgBouncycastleCryptoParamsRSAKeyParameters *)key {
  LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(self, key);
  return self;
}

- (instancetype)initWithJavaSecuritySpecRSAPrivateKeySpec:(JavaSecuritySpecRSAPrivateKeySpec *)spec {
  LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecuritySpecRSAPrivateKeySpec_(self, spec);
  return self;
}

- (instancetype)initWithJavaSecurityInterfacesRSAPrivateKey:(id<JavaSecurityInterfacesRSAPrivateKey>)key {
  LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecurityInterfacesRSAPrivateKey_(self, key);
  return self;
}

- (JavaMathBigInteger *)getModulus {
  return modulus_;
}

- (JavaMathBigInteger *)getPrivateExponent {
  return privateExponent_;
}

- (NSString *)getAlgorithm {
  return @"RSA";
}

- (NSString *)getFormat {
  return @"PKCS#8";
}

- (IOSByteArray *)getEncoded {
  return LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilKeyUtil_getEncodedPrivateKeyInfoWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, rsaEncryption), JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE)), new_LibOrgBouncycastleAsn1PkcsRSAPrivateKey_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([self getModulus], LibOrgBouncycastleJceProviderJCERSAPrivateKey_ZERO, [self getPrivateExponent], LibOrgBouncycastleJceProviderJCERSAPrivateKey_ZERO, LibOrgBouncycastleJceProviderJCERSAPrivateKey_ZERO, LibOrgBouncycastleJceProviderJCERSAPrivateKey_ZERO, LibOrgBouncycastleJceProviderJCERSAPrivateKey_ZERO, LibOrgBouncycastleJceProviderJCERSAPrivateKey_ZERO));
}

- (jboolean)isEqual:(id)o {
  if (!([JavaSecurityInterfacesRSAPrivateKey_class_() isInstance:o])) {
    return false;
  }
  if (o == self) {
    return true;
  }
  id<JavaSecurityInterfacesRSAPrivateKey> key = (id<JavaSecurityInterfacesRSAPrivateKey>) cast_check(o, JavaSecurityInterfacesRSAPrivateKey_class_());
  return [((JavaMathBigInteger *) nil_chk([self getModulus])) isEqual:[((id<JavaSecurityInterfacesRSAPrivateKey>) nil_chk(key)) getModulus]] && [((JavaMathBigInteger *) nil_chk([self getPrivateExponent])) isEqual:[key getPrivateExponent]];
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk([self getModulus])) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk([self getPrivateExponent])) hash]);
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
  LibOrgBouncycastleJceProviderJCERSAPrivateKey_readObjectWithJavaIoObjectInputStream_(self, inArg);
}

- (void)writeObjectWithJavaIoObjectOutputStream:(JavaIoObjectOutputStream *)outArg {
  LibOrgBouncycastleJceProviderJCERSAPrivateKey_writeObjectWithJavaIoObjectOutputStream_(self, outArg);
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
    { NULL, NULL, 0x0, -1, 2, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 5, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, 8, 9, -1, -1, -1, -1 },
    { NULL, "LJavaUtilEnumeration;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 10, 11, 12, -1, -1, -1 },
    { NULL, "V", 0x2, 13, 14, 15, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:);
  methods[2].selector = @selector(initWithJavaSecuritySpecRSAPrivateKeySpec:);
  methods[3].selector = @selector(initWithJavaSecurityInterfacesRSAPrivateKey:);
  methods[4].selector = @selector(getModulus);
  methods[5].selector = @selector(getPrivateExponent);
  methods[6].selector = @selector(getAlgorithm);
  methods[7].selector = @selector(getFormat);
  methods[8].selector = @selector(getEncoded);
  methods[9].selector = @selector(isEqual:);
  methods[10].selector = @selector(hash);
  methods[11].selector = @selector(setBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[12].selector = @selector(getBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[13].selector = @selector(getBagAttributeKeys);
  methods[14].selector = @selector(readObjectWithJavaIoObjectInputStream:);
  methods[15].selector = @selector(writeObjectWithJavaIoObjectOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = LibOrgBouncycastleJceProviderJCERSAPrivateKey_serialVersionUID, 0x18, -1, -1, -1, -1 },
    { "ZERO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0xa, -1, 16, -1, -1 },
    { "modulus_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "privateExponent_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "attrCarrier_", "LLibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl;", .constantValue.asLong = 0, 0x82, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoParamsRSAKeyParameters;", "LJavaSecuritySpecRSAPrivateKeySpec;", "LJavaSecurityInterfacesRSAPrivateKey;", "equals", "LNSObject;", "hashCode", "setBagAttribute", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Encodable;", "getBagAttribute", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "readObject", "LJavaIoObjectInputStream;", "LJavaIoIOException;LJavaLangClassNotFoundException;", "writeObject", "LJavaIoObjectOutputStream;", "LJavaIoIOException;", &LibOrgBouncycastleJceProviderJCERSAPrivateKey_ZERO };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceProviderJCERSAPrivateKey = { "JCERSAPrivateKey", "lib.org.bouncycastle.jce.provider", ptrTable, methods, fields, 7, 0x1, 16, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceProviderJCERSAPrivateKey;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJceProviderJCERSAPrivateKey class]) {
    LibOrgBouncycastleJceProviderJCERSAPrivateKey_ZERO = JavaMathBigInteger_valueOfWithLong_(0);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJceProviderJCERSAPrivateKey)
  }
}

@end

void LibOrgBouncycastleJceProviderJCERSAPrivateKey_init(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self) {
  NSObject_init(self);
  self->attrCarrier_ = new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl_init();
}

LibOrgBouncycastleJceProviderJCERSAPrivateKey *new_LibOrgBouncycastleJceProviderJCERSAPrivateKey_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderJCERSAPrivateKey, init)
}

LibOrgBouncycastleJceProviderJCERSAPrivateKey *create_LibOrgBouncycastleJceProviderJCERSAPrivateKey_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderJCERSAPrivateKey, init)
}

void LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self, LibOrgBouncycastleCryptoParamsRSAKeyParameters *key) {
  NSObject_init(self);
  self->attrCarrier_ = new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl_init();
  self->modulus_ = [((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(key)) getModulus];
  self->privateExponent_ = [key getExponent];
}

LibOrgBouncycastleJceProviderJCERSAPrivateKey *new_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleCryptoParamsRSAKeyParameters *key) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderJCERSAPrivateKey, initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_, key)
}

LibOrgBouncycastleJceProviderJCERSAPrivateKey *create_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleCryptoParamsRSAKeyParameters *key) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderJCERSAPrivateKey, initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_, key)
}

void LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecuritySpecRSAPrivateKeySpec_(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self, JavaSecuritySpecRSAPrivateKeySpec *spec) {
  NSObject_init(self);
  self->attrCarrier_ = new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl_init();
  self->modulus_ = [((JavaSecuritySpecRSAPrivateKeySpec *) nil_chk(spec)) getModulus];
  self->privateExponent_ = [spec getPrivateExponent];
}

LibOrgBouncycastleJceProviderJCERSAPrivateKey *new_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecuritySpecRSAPrivateKeySpec_(JavaSecuritySpecRSAPrivateKeySpec *spec) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderJCERSAPrivateKey, initWithJavaSecuritySpecRSAPrivateKeySpec_, spec)
}

LibOrgBouncycastleJceProviderJCERSAPrivateKey *create_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecuritySpecRSAPrivateKeySpec_(JavaSecuritySpecRSAPrivateKeySpec *spec) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderJCERSAPrivateKey, initWithJavaSecuritySpecRSAPrivateKeySpec_, spec)
}

void LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecurityInterfacesRSAPrivateKey_(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self, id<JavaSecurityInterfacesRSAPrivateKey> key) {
  NSObject_init(self);
  self->attrCarrier_ = new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl_init();
  self->modulus_ = [((id<JavaSecurityInterfacesRSAPrivateKey>) nil_chk(key)) getModulus];
  self->privateExponent_ = [key getPrivateExponent];
}

LibOrgBouncycastleJceProviderJCERSAPrivateKey *new_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecurityInterfacesRSAPrivateKey_(id<JavaSecurityInterfacesRSAPrivateKey> key) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderJCERSAPrivateKey, initWithJavaSecurityInterfacesRSAPrivateKey_, key)
}

LibOrgBouncycastleJceProviderJCERSAPrivateKey *create_LibOrgBouncycastleJceProviderJCERSAPrivateKey_initWithJavaSecurityInterfacesRSAPrivateKey_(id<JavaSecurityInterfacesRSAPrivateKey> key) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderJCERSAPrivateKey, initWithJavaSecurityInterfacesRSAPrivateKey_, key)
}

void LibOrgBouncycastleJceProviderJCERSAPrivateKey_readObjectWithJavaIoObjectInputStream_(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self, JavaIoObjectInputStream *inArg) {
  self->modulus_ = (JavaMathBigInteger *) cast_chk([((JavaIoObjectInputStream *) nil_chk(inArg)) readObject], [JavaMathBigInteger class]);
  self->attrCarrier_ = new_LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl_init();
  [self->attrCarrier_ readObjectWithJavaIoObjectInputStream:inArg];
  self->privateExponent_ = (JavaMathBigInteger *) cast_chk([inArg readObject], [JavaMathBigInteger class]);
}

void LibOrgBouncycastleJceProviderJCERSAPrivateKey_writeObjectWithJavaIoObjectOutputStream_(LibOrgBouncycastleJceProviderJCERSAPrivateKey *self, JavaIoObjectOutputStream *outArg) {
  [((JavaIoObjectOutputStream *) nil_chk(outArg)) writeObjectWithId:self->modulus_];
  [((LibOrgBouncycastleJcajceProviderAsymmetricUtilPKCS12BagAttributeCarrierImpl *) nil_chk(self->attrCarrier_)) writeObjectWithJavaIoObjectOutputStream:outArg];
  [outArg writeObjectWithId:self->privateExponent_];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceProviderJCERSAPrivateKey)
