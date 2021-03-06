//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/digests/SHA3Digest.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeccakDigest.h"
#include "SHA3Digest.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleCryptoDigestsSHA3Digest ()

+ (jint)checkBitLengthWithInt:(jint)bitLength;

@end

__attribute__((unused)) static jint LibOrgBouncycastleCryptoDigestsSHA3Digest_checkBitLengthWithInt_(jint bitLength);

@implementation LibOrgBouncycastleCryptoDigestsSHA3Digest

+ (jint)checkBitLengthWithInt:(jint)bitLength {
  return LibOrgBouncycastleCryptoDigestsSHA3Digest_checkBitLengthWithInt_(bitLength);
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoDigestsSHA3Digest_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithInt:(jint)bitLength {
  LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithInt_(self, bitLength);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoDigestsSHA3Digest:(LibOrgBouncycastleCryptoDigestsSHA3Digest *)source {
  LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithLibOrgBouncycastleCryptoDigestsSHA3Digest_(self, source);
  return self;
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$I", @"SHA3-", fixedOutputLength_);
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  [self absorbBitsWithInt:(jint) 0x02 withInt:2];
  return [super doFinalWithByteArray:outArg withInt:outOff];
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff
                    withByte:(jbyte)partialByte
                     withInt:(jint)partialBits {
  if (partialBits < 0 || partialBits > 7) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'partialBits' must be in the range [0,7]");
  }
  jint finalInput = (partialByte & ((JreLShift32(1, partialBits)) - 1)) | (JreLShift32((jint) 0x02, partialBits));
  jint finalBits = partialBits + 2;
  if (finalBits >= 8) {
    [self absorbWithByteArray:[IOSByteArray newArrayWithBytes:(jbyte[]){ (jbyte) finalInput } count:1] withInt:0 withInt:1];
    finalBits -= 8;
    JreURShiftAssignInt(&finalInput, 8);
  }
  return [super doFinalWithByteArray:outArg withInt:outOff withByte:(jbyte) finalInput withInt:finalBits];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "I", 0xa, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x4, 3, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(checkBitLengthWithInt:);
  methods[1].selector = @selector(init);
  methods[2].selector = @selector(initWithInt:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleCryptoDigestsSHA3Digest:);
  methods[4].selector = @selector(getAlgorithmName);
  methods[5].selector = @selector(doFinalWithByteArray:withInt:);
  methods[6].selector = @selector(doFinalWithByteArray:withInt:withByte:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "checkBitLength", "I", "LLibOrgBouncycastleCryptoDigestsSHA3Digest;", "doFinal", "[BI", "[BIBI" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoDigestsSHA3Digest = { "SHA3Digest", "lib.org.bouncycastle.crypto.digests", ptrTable, methods, NULL, 7, 0x1, 7, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoDigestsSHA3Digest;
}

@end

jint LibOrgBouncycastleCryptoDigestsSHA3Digest_checkBitLengthWithInt_(jint bitLength) {
  LibOrgBouncycastleCryptoDigestsSHA3Digest_initialize();
  switch (bitLength) {
    case 224:
    case 256:
    case 384:
    case 512:
    return bitLength;
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I$", @"'bitLength' ", bitLength, @" not supported for SHA-3"));
  }
}

void LibOrgBouncycastleCryptoDigestsSHA3Digest_init(LibOrgBouncycastleCryptoDigestsSHA3Digest *self) {
  LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithInt_(self, 256);
}

LibOrgBouncycastleCryptoDigestsSHA3Digest *new_LibOrgBouncycastleCryptoDigestsSHA3Digest_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsSHA3Digest, init)
}

LibOrgBouncycastleCryptoDigestsSHA3Digest *create_LibOrgBouncycastleCryptoDigestsSHA3Digest_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsSHA3Digest, init)
}

void LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithInt_(LibOrgBouncycastleCryptoDigestsSHA3Digest *self, jint bitLength) {
  LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithInt_(self, LibOrgBouncycastleCryptoDigestsSHA3Digest_checkBitLengthWithInt_(bitLength));
}

LibOrgBouncycastleCryptoDigestsSHA3Digest *new_LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithInt_(jint bitLength) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsSHA3Digest, initWithInt_, bitLength)
}

LibOrgBouncycastleCryptoDigestsSHA3Digest *create_LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithInt_(jint bitLength) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsSHA3Digest, initWithInt_, bitLength)
}

void LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithLibOrgBouncycastleCryptoDigestsSHA3Digest_(LibOrgBouncycastleCryptoDigestsSHA3Digest *self, LibOrgBouncycastleCryptoDigestsSHA3Digest *source) {
  LibOrgBouncycastleCryptoDigestsKeccakDigest_initWithLibOrgBouncycastleCryptoDigestsKeccakDigest_(self, source);
}

LibOrgBouncycastleCryptoDigestsSHA3Digest *new_LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithLibOrgBouncycastleCryptoDigestsSHA3Digest_(LibOrgBouncycastleCryptoDigestsSHA3Digest *source) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoDigestsSHA3Digest, initWithLibOrgBouncycastleCryptoDigestsSHA3Digest_, source)
}

LibOrgBouncycastleCryptoDigestsSHA3Digest *create_LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithLibOrgBouncycastleCryptoDigestsSHA3Digest_(LibOrgBouncycastleCryptoDigestsSHA3Digest *source) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoDigestsSHA3Digest, initWithLibOrgBouncycastleCryptoDigestsSHA3Digest_, source)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoDigestsSHA3Digest)
