//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/util/AsymmetricKeyInfoConverter.java
//

#include "AsymmetricKeyInfoConverter.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter : NSObject

@end

@implementation LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LJavaSecurityPrivateKey;", 0x401, 0, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x401, 3, 4, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:);
  methods[1].selector = @selector(generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "generatePrivate", "LLibOrgBouncycastleAsn1PkcsPrivateKeyInfo;", "LJavaIoIOException;", "generatePublic", "LLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter = { "AsymmetricKeyInfoConverter", "lib.org.bouncycastle.jcajce.provider.util", ptrTable, methods, NULL, 7, 0x609, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter)
