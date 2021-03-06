//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/util/GOST3410Util.java
//

#include "AsymmetricKeyParameter.h"
#include "GOST3410Parameters.h"
#include "GOST3410Params.h"
#include "GOST3410PrivateKey.h"
#include "GOST3410PrivateKeyParameters.h"
#include "GOST3410PublicKey.h"
#include "GOST3410PublicKeyParameterSetSpec.h"
#include "GOST3410PublicKeyParameters.h"
#include "GOST3410Util.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "java/security/InvalidKeyException.h"
#include "java/security/PrivateKey.h"
#include "java/security/PublicKey.h"

@implementation LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePublicKeyParameterWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key {
  return LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util_generatePublicKeyParameterWithJavaSecurityPublicKey_(key);
}

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePrivateKeyParameterWithJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)key {
  return LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util_generatePrivateKeyParameterWithJavaSecurityPrivateKey_(key);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", 0x9, 3, 4, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generatePublicKeyParameterWithJavaSecurityPublicKey:);
  methods[2].selector = @selector(generatePrivateKeyParameterWithJavaSecurityPrivateKey:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "generatePublicKeyParameter", "LJavaSecurityPublicKey;", "LJavaSecurityInvalidKeyException;", "generatePrivateKeyParameter", "LJavaSecurityPrivateKey;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util = { "GOST3410Util", "lib.org.bouncycastle.jcajce.provider.asymmetric.util", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util *new_LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util *create_LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util, init)
}

LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util_generatePublicKeyParameterWithJavaSecurityPublicKey_(id<JavaSecurityPublicKey> key) {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util_initialize();
  if ([LibOrgBouncycastleJceInterfacesGOST3410PublicKey_class_() isInstance:key]) {
    id<LibOrgBouncycastleJceInterfacesGOST3410PublicKey> k = (id<LibOrgBouncycastleJceInterfacesGOST3410PublicKey>) cast_check(key, LibOrgBouncycastleJceInterfacesGOST3410PublicKey_class_());
    LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *p = [((id<LibOrgBouncycastleJceInterfacesGOST3410Params>) nil_chk([((id<LibOrgBouncycastleJceInterfacesGOST3410PublicKey>) nil_chk(k)) getParameters])) getPublicKeyParameters];
    return new_LibOrgBouncycastleCryptoParamsGOST3410PublicKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_([k getY], new_LibOrgBouncycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *) nil_chk(p)) getP], [p getQ], [p getA]));
  }
  @throw new_JavaSecurityInvalidKeyException_initWithNSString_(JreStrcat("$$", @"can't identify GOST3410 public key: ", [[((id<JavaSecurityPublicKey>) nil_chk(key)) java_getClass] getName]));
}

LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util_generatePrivateKeyParameterWithJavaSecurityPrivateKey_(id<JavaSecurityPrivateKey> key) {
  LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util_initialize();
  if ([LibOrgBouncycastleJceInterfacesGOST3410PrivateKey_class_() isInstance:key]) {
    id<LibOrgBouncycastleJceInterfacesGOST3410PrivateKey> k = (id<LibOrgBouncycastleJceInterfacesGOST3410PrivateKey>) cast_check(key, LibOrgBouncycastleJceInterfacesGOST3410PrivateKey_class_());
    LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *p = [((id<LibOrgBouncycastleJceInterfacesGOST3410Params>) nil_chk([((id<LibOrgBouncycastleJceInterfacesGOST3410PrivateKey>) nil_chk(k)) getParameters])) getPublicKeyParameters];
    return new_LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters_initWithJavaMathBigInteger_withLibOrgBouncycastleCryptoParamsGOST3410Parameters_([k getX], new_LibOrgBouncycastleCryptoParamsGOST3410Parameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *) nil_chk(p)) getP], [p getQ], [p getA]));
  }
  @throw new_JavaSecurityInvalidKeyException_initWithNSString_(@"can't identify GOST3410 private key.");
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricUtilGOST3410Util)
