//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/qtesla/QTESLAKeyFactorySpi.java
//

#include "ASN1Primitive.h"
#include "BCqTESLAPrivateKey.h"
#include "BCqTESLAPublicKey.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PrivateKeyInfo.h"
#include "QTESLAKeyFactorySpi.h"
#include "SubjectPublicKeyInfo.h"
#include "java/lang/Exception.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/Key.h"
#include "java/security/KeyFactorySpi.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"
#include "java/security/spec/InvalidKeySpecException.h"
#include "java/security/spec/KeySpec.h"
#include "java/security/spec/PKCS8EncodedKeySpec.h"
#include "java/security/spec/X509EncodedKeySpec.h"

@implementation LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[JavaSecuritySpecPKCS8EncodedKeySpec class]]) {
    IOSByteArray *encKey = [((JavaSecuritySpecPKCS8EncodedKeySpec *) nil_chk(((JavaSecuritySpecPKCS8EncodedKeySpec *) keySpec))) getEncoded];
    @try {
      return [self generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:LibOrgBouncycastleAsn1PkcsPrivateKeyInfo_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(encKey))];
    }
    @catch (JavaLangException *e) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_([e description]);
    }
  }
  @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@C", @"Unsupported key specification: ", [((id<JavaSecuritySpecKeySpec>) nil_chk(keySpec)) java_getClass], '.'));
}

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec {
  if ([keySpec isKindOfClass:[JavaSecuritySpecX509EncodedKeySpec class]]) {
    IOSByteArray *encKey = [((JavaSecuritySpecX509EncodedKeySpec *) nil_chk(((JavaSecuritySpecX509EncodedKeySpec *) keySpec))) getEncoded];
    @try {
      return [self generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_getInstanceWithId_(encKey)];
    }
    @catch (JavaLangException *e) {
      @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_([e description]);
    }
  }
  @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@C", @"Unknown key specification: ", keySpec, '.'));
}

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)keySpec {
  if ([key isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderQteslaBCqTESLAPrivateKey class]]) {
    if ([JavaSecuritySpecPKCS8EncodedKeySpec_class_() isAssignableFrom:keySpec]) {
      return new_JavaSecuritySpecPKCS8EncodedKeySpec_initWithByteArray_([((id<JavaSecurityKey>) nil_chk(key)) getEncoded]);
    }
  }
  else if ([key isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderQteslaBCqTESLAPublicKey class]]) {
    if ([JavaSecuritySpecX509EncodedKeySpec_class_() isAssignableFrom:keySpec]) {
      return new_JavaSecuritySpecX509EncodedKeySpec_initWithByteArray_([((id<JavaSecurityKey>) nil_chk(key)) getEncoded]);
    }
  }
  else {
    @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@C", @"Unsupported key type: ", [((id<JavaSecurityKey>) nil_chk(key)) java_getClass], '.'));
  }
  @throw new_JavaSecuritySpecInvalidKeySpecException_initWithNSString_(JreStrcat("$@C", @"Unknown key specification: ", keySpec, '.'));
}

- (id<JavaSecurityKey>)engineTranslateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key {
  if ([key isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderQteslaBCqTESLAPrivateKey class]] || [key isKindOfClass:[LibOrgBouncycastlePqcJcajceProviderQteslaBCqTESLAPublicKey class]]) {
    return key;
  }
  @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"Unsupported key type");
}

- (id<JavaSecurityPrivateKey>)generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)keyInfo {
  return new_LibOrgBouncycastlePqcJcajceProviderQteslaBCqTESLAPrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(keyInfo);
}

- (id<JavaSecurityPublicKey>)generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)keyInfo {
  return new_LibOrgBouncycastlePqcJcajceProviderQteslaBCqTESLAPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(keyInfo);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x1, 3, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecKeySpec;", 0x11, 4, 5, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityKey;", 0x11, 6, 7, 8, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x1, 9, 10, 11, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x1, 12, 13, 11, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineGeneratePrivateWithJavaSecuritySpecKeySpec:);
  methods[2].selector = @selector(engineGeneratePublicWithJavaSecuritySpecKeySpec:);
  methods[3].selector = @selector(engineGetKeySpecWithJavaSecurityKey:withIOSClass:);
  methods[4].selector = @selector(engineTranslateKeyWithJavaSecurityKey:);
  methods[5].selector = @selector(generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:);
  methods[6].selector = @selector(generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "engineGeneratePrivate", "LJavaSecuritySpecKeySpec;", "LJavaSecuritySpecInvalidKeySpecException;", "engineGeneratePublic", "engineGetKeySpec", "LJavaSecurityKey;LIOSClass;", "engineTranslateKey", "LJavaSecurityKey;", "LJavaSecurityInvalidKeyException;", "generatePrivate", "LLibOrgBouncycastleAsn1PkcsPrivateKeyInfo;", "LJavaIoIOException;", "generatePublic", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi = { "QTESLAKeyFactorySpi", "lib.org.bouncycastle.pqc.jcajce.provider.qtesla", ptrTable, methods, NULL, 7, 0x1, 7, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi;
}

@end

void LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi_init(LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi *self) {
  JavaSecurityKeyFactorySpi_init(self);
}

LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi *new_LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi, init)
}

LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi *create_LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcJcajceProviderQteslaQTESLAKeyFactorySpi)