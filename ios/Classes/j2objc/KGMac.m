//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/macs/KGMac.java
//

#include "AEADParameters.h"
#include "BlockCipher.h"
#include "CipherParameters.h"
#include "IOSPrimitiveArray.h"
#include "InvalidCipherTextException.h"
#include "J2ObjC_source.h"
#include "KGCMBlockCipher.h"
#include "KGMac.h"
#include "KeyParameter.h"
#include "ParametersWithIV.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"

@interface LibOrgBouncycastleCryptoMacsKGMac () {
 @public
  LibOrgBouncycastleCryptoModesKGCMBlockCipher *cipher_;
  jint macSizeBits_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoMacsKGMac, cipher_, LibOrgBouncycastleCryptoModesKGCMBlockCipher *)

@implementation LibOrgBouncycastleCryptoMacsKGMac

- (instancetype)initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher:(LibOrgBouncycastleCryptoModesKGCMBlockCipher *)cipher {
  LibOrgBouncycastleCryptoMacsKGMac_initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_(self, cipher);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher:(LibOrgBouncycastleCryptoModesKGCMBlockCipher *)cipher
                                                             withInt:(jint)macSizeBits {
  LibOrgBouncycastleCryptoMacsKGMac_initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_withInt_(self, cipher, macSizeBits);
  return self;
}

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  if ([params isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithIV class]]) {
    LibOrgBouncycastleCryptoParamsParametersWithIV *param = (LibOrgBouncycastleCryptoParamsParametersWithIV *) params;
    IOSByteArray *iv = [((LibOrgBouncycastleCryptoParamsParametersWithIV *) nil_chk(param)) getIV];
    LibOrgBouncycastleCryptoParamsKeyParameter *keyParam = (LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk([param getParameters], [LibOrgBouncycastleCryptoParamsKeyParameter class]);
    [((LibOrgBouncycastleCryptoModesKGCMBlockCipher *) nil_chk(cipher_)) init__WithBoolean:true withLibOrgBouncycastleCryptoCipherParameters:new_LibOrgBouncycastleCryptoParamsAEADParameters_initWithLibOrgBouncycastleCryptoParamsKeyParameter_withInt_withByteArray_(keyParam, macSizeBits_, iv)];
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"KGMAC requires ParametersWithIV");
  }
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$$", [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk([((LibOrgBouncycastleCryptoModesKGCMBlockCipher *) nil_chk(cipher_)) getUnderlyingCipher])) getAlgorithmName], @"-KGMAC");
}

- (jint)getMacSize {
  return macSizeBits_ / 8;
}

- (void)updateWithByte:(jbyte)inArg {
  [((LibOrgBouncycastleCryptoModesKGCMBlockCipher *) nil_chk(cipher_)) processAADByteWithByte:inArg];
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len {
  [((LibOrgBouncycastleCryptoModesKGCMBlockCipher *) nil_chk(cipher_)) processAADBytesWithByteArray:inArg withInt:inOff withInt:len];
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  @try {
    return [((LibOrgBouncycastleCryptoModesKGCMBlockCipher *) nil_chk(cipher_)) doFinalWithByteArray:outArg withInt:outOff];
  }
  @catch (LibOrgBouncycastleCryptoInvalidCipherTextException *e) {
    @throw new_JavaLangIllegalStateException_initWithNSString_([e description]);
  }
}

- (void)reset {
  [((LibOrgBouncycastleCryptoModesKGCMBlockCipher *) nil_chk(cipher_)) reset];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, 4, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, 7, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 8, 9, -1, -1, -1 },
    { NULL, "I", 0x1, 10, 11, 9, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher:withInt:);
  methods[2].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[3].selector = @selector(getAlgorithmName);
  methods[4].selector = @selector(getMacSize);
  methods[5].selector = @selector(updateWithByte:);
  methods[6].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[7].selector = @selector(doFinalWithByteArray:withInt:);
  methods[8].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cipher_", "LLibOrgBouncycastleCryptoModesKGCMBlockCipher;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "macSizeBits_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoModesKGCMBlockCipher;", "LLibOrgBouncycastleCryptoModesKGCMBlockCipher;I", "init", "LLibOrgBouncycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "update", "B", "LJavaLangIllegalStateException;", "[BII", "LLibOrgBouncycastleCryptoDataLengthException;LJavaLangIllegalStateException;", "doFinal", "[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoMacsKGMac = { "KGMac", "lib.org.bouncycastle.crypto.macs", ptrTable, methods, fields, 7, 0x1, 9, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoMacsKGMac;
}

@end

void LibOrgBouncycastleCryptoMacsKGMac_initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_(LibOrgBouncycastleCryptoMacsKGMac *self, LibOrgBouncycastleCryptoModesKGCMBlockCipher *cipher) {
  NSObject_init(self);
  self->cipher_ = cipher;
  self->macSizeBits_ = [((id<LibOrgBouncycastleCryptoBlockCipher>) nil_chk([((LibOrgBouncycastleCryptoModesKGCMBlockCipher *) nil_chk(cipher)) getUnderlyingCipher])) getBlockSize] * 8;
}

LibOrgBouncycastleCryptoMacsKGMac *new_LibOrgBouncycastleCryptoMacsKGMac_initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_(LibOrgBouncycastleCryptoModesKGCMBlockCipher *cipher) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoMacsKGMac, initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_, cipher)
}

LibOrgBouncycastleCryptoMacsKGMac *create_LibOrgBouncycastleCryptoMacsKGMac_initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_(LibOrgBouncycastleCryptoModesKGCMBlockCipher *cipher) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoMacsKGMac, initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_, cipher)
}

void LibOrgBouncycastleCryptoMacsKGMac_initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_withInt_(LibOrgBouncycastleCryptoMacsKGMac *self, LibOrgBouncycastleCryptoModesKGCMBlockCipher *cipher, jint macSizeBits) {
  NSObject_init(self);
  self->cipher_ = cipher;
  self->macSizeBits_ = macSizeBits;
}

LibOrgBouncycastleCryptoMacsKGMac *new_LibOrgBouncycastleCryptoMacsKGMac_initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_withInt_(LibOrgBouncycastleCryptoModesKGCMBlockCipher *cipher, jint macSizeBits) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoMacsKGMac, initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_withInt_, cipher, macSizeBits)
}

LibOrgBouncycastleCryptoMacsKGMac *create_LibOrgBouncycastleCryptoMacsKGMac_initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_withInt_(LibOrgBouncycastleCryptoModesKGCMBlockCipher *cipher, jint macSizeBits) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoMacsKGMac, initWithLibOrgBouncycastleCryptoModesKGCMBlockCipher_withInt_, cipher, macSizeBits)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoMacsKGMac)
