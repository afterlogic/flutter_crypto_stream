//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/PGPDataEncryptorBuilder.java
//

#include "J2ObjC_source.h"
#include "PGPDataEncryptorBuilder.h"

@interface LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder : NSObject

@end

@implementation LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "I", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPGPDataEncryptor;", 0x401, 0, 1, 2, -1, -1, -1 },
    { NULL, "LJavaSecuritySecureRandom;", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getAlgorithm);
  methods[1].selector = @selector(buildWithByteArray:);
  methods[2].selector = @selector(getSecureRandom);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "build", "[B", "LLibOrgBouncycastleOpenpgpPGPException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder = { "PGPDataEncryptorBuilder", "lib.org.bouncycastle.openpgp.operator", ptrTable, methods, NULL, 7, 0x609, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorPGPDataEncryptorBuilder)
