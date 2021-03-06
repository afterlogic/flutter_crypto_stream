//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/OldIESEngine.java
//

#include "BasicAgreement.h"
#include "BufferedBlockCipher.h"
#include "DerivationFunction.h"
#include "IESEngine.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "Mac.h"
#include "OldIESEngine.h"
#include "Pack.h"

@implementation LibOrgBouncycastleCryptoEnginesOldIESEngine

- (instancetype)initWithLibOrgBouncycastleCryptoBasicAgreement:(id<LibOrgBouncycastleCryptoBasicAgreement>)agree
                withLibOrgBouncycastleCryptoDerivationFunction:(id<LibOrgBouncycastleCryptoDerivationFunction>)kdf
                               withLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)mac {
  LibOrgBouncycastleCryptoEnginesOldIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_(self, agree, kdf, mac);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoBasicAgreement:(id<LibOrgBouncycastleCryptoBasicAgreement>)agree
                withLibOrgBouncycastleCryptoDerivationFunction:(id<LibOrgBouncycastleCryptoDerivationFunction>)kdf
                               withLibOrgBouncycastleCryptoMac:(id<LibOrgBouncycastleCryptoMac>)mac
               withLibOrgBouncycastleCryptoBufferedBlockCipher:(LibOrgBouncycastleCryptoBufferedBlockCipher *)cipher {
  LibOrgBouncycastleCryptoEnginesOldIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_(self, agree, kdf, mac, cipher);
  return self;
}

- (IOSByteArray *)getLengthTagWithByteArray:(IOSByteArray *)p2 {
  IOSByteArray *L2 = [IOSByteArray newArrayWithLength:4];
  if (p2 != nil) {
    LibOrgBouncycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(p2->size_ * 8, L2, 0);
  }
  return L2;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoBasicAgreement:withLibOrgBouncycastleCryptoDerivationFunction:withLibOrgBouncycastleCryptoMac:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoBasicAgreement:withLibOrgBouncycastleCryptoDerivationFunction:withLibOrgBouncycastleCryptoMac:withLibOrgBouncycastleCryptoBufferedBlockCipher:);
  methods[2].selector = @selector(getLengthTagWithByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoBasicAgreement;LLibOrgBouncycastleCryptoDerivationFunction;LLibOrgBouncycastleCryptoMac;", "LLibOrgBouncycastleCryptoBasicAgreement;LLibOrgBouncycastleCryptoDerivationFunction;LLibOrgBouncycastleCryptoMac;LLibOrgBouncycastleCryptoBufferedBlockCipher;", "getLengthTag", "[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesOldIESEngine = { "OldIESEngine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesOldIESEngine;
}

@end

void LibOrgBouncycastleCryptoEnginesOldIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_(LibOrgBouncycastleCryptoEnginesOldIESEngine *self, id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac) {
  LibOrgBouncycastleCryptoEnginesIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_(self, agree, kdf, mac);
}

LibOrgBouncycastleCryptoEnginesOldIESEngine *new_LibOrgBouncycastleCryptoEnginesOldIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_(id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesOldIESEngine, initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_, agree, kdf, mac)
}

LibOrgBouncycastleCryptoEnginesOldIESEngine *create_LibOrgBouncycastleCryptoEnginesOldIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_(id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesOldIESEngine, initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_, agree, kdf, mac)
}

void LibOrgBouncycastleCryptoEnginesOldIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_(LibOrgBouncycastleCryptoEnginesOldIESEngine *self, id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher) {
  LibOrgBouncycastleCryptoEnginesIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_(self, agree, kdf, mac, cipher);
}

LibOrgBouncycastleCryptoEnginesOldIESEngine *new_LibOrgBouncycastleCryptoEnginesOldIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_(id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesOldIESEngine, initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_, agree, kdf, mac, cipher)
}

LibOrgBouncycastleCryptoEnginesOldIESEngine *create_LibOrgBouncycastleCryptoEnginesOldIESEngine_initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_(id<LibOrgBouncycastleCryptoBasicAgreement> agree, id<LibOrgBouncycastleCryptoDerivationFunction> kdf, id<LibOrgBouncycastleCryptoMac> mac, LibOrgBouncycastleCryptoBufferedBlockCipher *cipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesOldIESEngine, initWithLibOrgBouncycastleCryptoBasicAgreement_withLibOrgBouncycastleCryptoDerivationFunction_withLibOrgBouncycastleCryptoMac_withLibOrgBouncycastleCryptoBufferedBlockCipher_, agree, kdf, mac, cipher)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesOldIESEngine)
