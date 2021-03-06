//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/sphincs/SPHINCS256KeyGenerationParameters.java
//

#include "Digest.h"
#include "J2ObjC_source.h"
#include "KeyGenerationParameters.h"
#include "SPHINCS256Config.h"
#include "SPHINCS256KeyGenerationParameters.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters () {
 @public
  id<LibOrgBouncycastleCryptoDigest> treeDigest_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters, treeDigest_, id<LibOrgBouncycastleCryptoDigest>)

@implementation LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
              withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)treeDigest {
  LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoDigest_(self, random, treeDigest);
  return self;
}

- (id<LibOrgBouncycastleCryptoDigest>)getTreeDigest {
  return treeDigest_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoDigest;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecuritySecureRandom:withLibOrgBouncycastleCryptoDigest:);
  methods[1].selector = @selector(getTreeDigest);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "treeDigest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecuritySecureRandom;LLibOrgBouncycastleCryptoDigest;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters = { "SPHINCS256KeyGenerationParameters", "lib.org.bouncycastle.pqc.crypto.sphincs", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters;
}

@end

void LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters *self, JavaSecuritySecureRandom *random, id<LibOrgBouncycastleCryptoDigest> treeDigest) {
  LibOrgBouncycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_(self, random, LibOrgBouncycastlePqcCryptoSphincsSPHINCS256Config_CRYPTO_PUBLICKEYBYTES * 8);
  self->treeDigest_ = treeDigest;
}

LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters *new_LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoDigest_(JavaSecuritySecureRandom *random, id<LibOrgBouncycastleCryptoDigest> treeDigest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters, initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoDigest_, random, treeDigest)
}

LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters *create_LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoDigest_(JavaSecuritySecureRandom *random, id<LibOrgBouncycastleCryptoDigest> treeDigest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters, initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoDigest_, random, treeDigest)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoSphincsSPHINCS256KeyGenerationParameters)
