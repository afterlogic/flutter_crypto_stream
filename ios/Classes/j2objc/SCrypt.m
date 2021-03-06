//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/SCrypt.java
//

#include "Arrays.h"
#include "CipherParameters.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "PBEParametersGenerator.h"
#include "PKCS5S2ParametersGenerator.h"
#include "Pack.h"
#include "SCrypt.h"
#include "SHA256Digest.h"
#include "Salsa20Engine.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoGeneratorsSCrypt ()

- (instancetype)init;

+ (IOSByteArray *)MFcryptWithByteArray:(IOSByteArray *)P
                         withByteArray:(IOSByteArray *)S
                               withInt:(jint)N
                               withInt:(jint)r
                               withInt:(jint)p
                               withInt:(jint)dkLen;

+ (IOSByteArray *)SingleIterationPBKDF2WithByteArray:(IOSByteArray *)P
                                       withByteArray:(IOSByteArray *)S
                                             withInt:(jint)dkLen;

+ (void)SMixWithIntArray:(IOSIntArray *)B
                 withInt:(jint)BOff
                 withInt:(jint)N
                 withInt:(jint)r;

+ (void)BlockMixWithIntArray:(IOSIntArray *)B
                withIntArray:(IOSIntArray *)X1
                withIntArray:(IOSIntArray *)X2
                withIntArray:(IOSIntArray *)Y
                     withInt:(jint)r;

+ (void)XorWithIntArray:(IOSIntArray *)a
           withIntArray:(IOSIntArray *)b
                withInt:(jint)bOff
           withIntArray:(IOSIntArray *)output;

+ (void)ClearWithByteArray:(IOSByteArray *)array;

+ (void)ClearWithIntArray:(IOSIntArray *)array;

+ (void)ClearAllWithIntArray2:(IOSObjectArray *)arrays;

+ (jboolean)isPowerOf2WithInt:(jint)x;

@end

__attribute__((unused)) static void LibOrgBouncycastleCryptoGeneratorsSCrypt_init(LibOrgBouncycastleCryptoGeneratorsSCrypt *self);

__attribute__((unused)) static LibOrgBouncycastleCryptoGeneratorsSCrypt *new_LibOrgBouncycastleCryptoGeneratorsSCrypt_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoGeneratorsSCrypt *create_LibOrgBouncycastleCryptoGeneratorsSCrypt_init(void);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoGeneratorsSCrypt_MFcryptWithByteArray_withByteArray_withInt_withInt_withInt_withInt_(IOSByteArray *P, IOSByteArray *S, jint N, jint r, jint p, jint dkLen);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoGeneratorsSCrypt_SingleIterationPBKDF2WithByteArray_withByteArray_withInt_(IOSByteArray *P, IOSByteArray *S, jint dkLen);

__attribute__((unused)) static void LibOrgBouncycastleCryptoGeneratorsSCrypt_SMixWithIntArray_withInt_withInt_withInt_(IOSIntArray *B, jint BOff, jint N, jint r);

__attribute__((unused)) static void LibOrgBouncycastleCryptoGeneratorsSCrypt_BlockMixWithIntArray_withIntArray_withIntArray_withIntArray_withInt_(IOSIntArray *B, IOSIntArray *X1, IOSIntArray *X2, IOSIntArray *Y, jint r);

__attribute__((unused)) static void LibOrgBouncycastleCryptoGeneratorsSCrypt_XorWithIntArray_withIntArray_withInt_withIntArray_(IOSIntArray *a, IOSIntArray *b, jint bOff, IOSIntArray *output);

__attribute__((unused)) static void LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearWithByteArray_(IOSByteArray *array);

__attribute__((unused)) static void LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearWithIntArray_(IOSIntArray *array);

__attribute__((unused)) static void LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearAllWithIntArray2_(IOSObjectArray *arrays);

__attribute__((unused)) static jboolean LibOrgBouncycastleCryptoGeneratorsSCrypt_isPowerOf2WithInt_(jint x);

@implementation LibOrgBouncycastleCryptoGeneratorsSCrypt

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSByteArray *)generateWithByteArray:(IOSByteArray *)P
                          withByteArray:(IOSByteArray *)S
                                withInt:(jint)N
                                withInt:(jint)r
                                withInt:(jint)p
                                withInt:(jint)dkLen {
  return LibOrgBouncycastleCryptoGeneratorsSCrypt_generateWithByteArray_withByteArray_withInt_withInt_withInt_withInt_(P, S, N, r, p, dkLen);
}

+ (IOSByteArray *)MFcryptWithByteArray:(IOSByteArray *)P
                         withByteArray:(IOSByteArray *)S
                               withInt:(jint)N
                               withInt:(jint)r
                               withInt:(jint)p
                               withInt:(jint)dkLen {
  return LibOrgBouncycastleCryptoGeneratorsSCrypt_MFcryptWithByteArray_withByteArray_withInt_withInt_withInt_withInt_(P, S, N, r, p, dkLen);
}

+ (IOSByteArray *)SingleIterationPBKDF2WithByteArray:(IOSByteArray *)P
                                       withByteArray:(IOSByteArray *)S
                                             withInt:(jint)dkLen {
  return LibOrgBouncycastleCryptoGeneratorsSCrypt_SingleIterationPBKDF2WithByteArray_withByteArray_withInt_(P, S, dkLen);
}

+ (void)SMixWithIntArray:(IOSIntArray *)B
                 withInt:(jint)BOff
                 withInt:(jint)N
                 withInt:(jint)r {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_SMixWithIntArray_withInt_withInt_withInt_(B, BOff, N, r);
}

+ (void)BlockMixWithIntArray:(IOSIntArray *)B
                withIntArray:(IOSIntArray *)X1
                withIntArray:(IOSIntArray *)X2
                withIntArray:(IOSIntArray *)Y
                     withInt:(jint)r {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_BlockMixWithIntArray_withIntArray_withIntArray_withIntArray_withInt_(B, X1, X2, Y, r);
}

+ (void)XorWithIntArray:(IOSIntArray *)a
           withIntArray:(IOSIntArray *)b
                withInt:(jint)bOff
           withIntArray:(IOSIntArray *)output {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_XorWithIntArray_withIntArray_withInt_withIntArray_(a, b, bOff, output);
}

+ (void)ClearWithByteArray:(IOSByteArray *)array {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearWithByteArray_(array);
}

+ (void)ClearWithIntArray:(IOSIntArray *)array {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearWithIntArray_(array);
}

+ (void)ClearAllWithIntArray2:(IOSObjectArray *)arrays {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearAllWithIntArray2_(arrays);
}

+ (jboolean)isPowerOf2WithInt:(jint)x {
  return LibOrgBouncycastleCryptoGeneratorsSCrypt_isPowerOf2WithInt_(x);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0xa, 2, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0xa, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 11, 12, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 11, 13, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 14, 15, -1, -1, -1, -1 },
    { NULL, "Z", 0xa, 16, 17, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generateWithByteArray:withByteArray:withInt:withInt:withInt:withInt:);
  methods[2].selector = @selector(MFcryptWithByteArray:withByteArray:withInt:withInt:withInt:withInt:);
  methods[3].selector = @selector(SingleIterationPBKDF2WithByteArray:withByteArray:withInt:);
  methods[4].selector = @selector(SMixWithIntArray:withInt:withInt:withInt:);
  methods[5].selector = @selector(BlockMixWithIntArray:withIntArray:withIntArray:withIntArray:withInt:);
  methods[6].selector = @selector(XorWithIntArray:withIntArray:withInt:withIntArray:);
  methods[7].selector = @selector(ClearWithByteArray:);
  methods[8].selector = @selector(ClearWithIntArray:);
  methods[9].selector = @selector(ClearAllWithIntArray2:);
  methods[10].selector = @selector(isPowerOf2WithInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "generate", "[B[BIIII", "MFcrypt", "SingleIterationPBKDF2", "[B[BI", "SMix", "[IIII", "BlockMix", "[I[I[I[II", "Xor", "[I[II[I", "Clear", "[B", "[I", "ClearAll", "[[I", "isPowerOf2", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsSCrypt = { "SCrypt", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, NULL, 7, 0x1, 11, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsSCrypt;
}

@end

void LibOrgBouncycastleCryptoGeneratorsSCrypt_init(LibOrgBouncycastleCryptoGeneratorsSCrypt *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoGeneratorsSCrypt *new_LibOrgBouncycastleCryptoGeneratorsSCrypt_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsSCrypt, init)
}

LibOrgBouncycastleCryptoGeneratorsSCrypt *create_LibOrgBouncycastleCryptoGeneratorsSCrypt_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsSCrypt, init)
}

IOSByteArray *LibOrgBouncycastleCryptoGeneratorsSCrypt_generateWithByteArray_withByteArray_withInt_withInt_withInt_withInt_(IOSByteArray *P, IOSByteArray *S, jint N, jint r, jint p, jint dkLen) {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_initialize();
  if (P == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Passphrase P must be provided.");
  }
  if (S == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Salt S must be provided.");
  }
  if (N <= 1 || !LibOrgBouncycastleCryptoGeneratorsSCrypt_isPowerOf2WithInt_(N)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Cost parameter N must be > 1 and a power of 2");
  }
  if (r == 1 && N >= 65536) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Cost parameter N must be > 1 and < 65536.");
  }
  if (r < 1) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Block size r must be >= 1.");
  }
  jint maxParallel = JavaLangInteger_MAX_VALUE / (128 * r * 8);
  if (p < 1 || p > maxParallel) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I$IC", @"Parallelisation parameter p must be >= 1 and <= ", maxParallel, @" (based on block size r of ", r, ')'));
  }
  if (dkLen < 1) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Generated key length dkLen must be >= 1.");
  }
  return LibOrgBouncycastleCryptoGeneratorsSCrypt_MFcryptWithByteArray_withByteArray_withInt_withInt_withInt_withInt_(P, S, N, r, p, dkLen);
}

IOSByteArray *LibOrgBouncycastleCryptoGeneratorsSCrypt_MFcryptWithByteArray_withByteArray_withInt_withInt_withInt_withInt_(IOSByteArray *P, IOSByteArray *S, jint N, jint r, jint p, jint dkLen) {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_initialize();
  jint MFLenBytes = r * 128;
  IOSByteArray *bytes = LibOrgBouncycastleCryptoGeneratorsSCrypt_SingleIterationPBKDF2WithByteArray_withByteArray_withInt_(P, S, p * MFLenBytes);
  IOSIntArray *B = nil;
  @try {
    jint BLen = JreURShift32(((IOSByteArray *) nil_chk(bytes))->size_, 2);
    B = [IOSIntArray newArrayWithLength:BLen];
    LibOrgBouncycastleUtilPack_littleEndianToIntWithByteArray_withInt_withIntArray_(bytes, 0, B);
    jint MFLenWords = JreURShift32(MFLenBytes, 2);
    for (jint BOff = 0; BOff < BLen; BOff += MFLenWords) {
      LibOrgBouncycastleCryptoGeneratorsSCrypt_SMixWithIntArray_withInt_withInt_withInt_(B, BOff, N, r);
    }
    LibOrgBouncycastleUtilPack_intToLittleEndianWithIntArray_withByteArray_withInt_(B, bytes, 0);
    return LibOrgBouncycastleCryptoGeneratorsSCrypt_SingleIterationPBKDF2WithByteArray_withByteArray_withInt_(P, bytes, dkLen);
  }
  @finally {
    LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearWithByteArray_(bytes);
    LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearWithIntArray_(B);
  }
}

IOSByteArray *LibOrgBouncycastleCryptoGeneratorsSCrypt_SingleIterationPBKDF2WithByteArray_withByteArray_withInt_(IOSByteArray *P, IOSByteArray *S, jint dkLen) {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_initialize();
  LibOrgBouncycastleCryptoPBEParametersGenerator *pGen = new_LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(new_LibOrgBouncycastleCryptoDigestsSHA256Digest_init());
  [pGen init__WithByteArray:P withByteArray:S withInt:1];
  LibOrgBouncycastleCryptoParamsKeyParameter *key = (LibOrgBouncycastleCryptoParamsKeyParameter *) cast_chk([pGen generateDerivedMacParametersWithInt:dkLen * 8], [LibOrgBouncycastleCryptoParamsKeyParameter class]);
  return [((LibOrgBouncycastleCryptoParamsKeyParameter *) nil_chk(key)) getKey];
}

void LibOrgBouncycastleCryptoGeneratorsSCrypt_SMixWithIntArray_withInt_withInt_withInt_(IOSIntArray *B, jint BOff, jint N, jint r) {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_initialize();
  jint BCount = r * 32;
  IOSIntArray *blockX1 = [IOSIntArray newArrayWithLength:16];
  IOSIntArray *blockX2 = [IOSIntArray newArrayWithLength:16];
  IOSIntArray *blockY = [IOSIntArray newArrayWithLength:BCount];
  IOSIntArray *X = [IOSIntArray newArrayWithLength:BCount];
  IOSObjectArray *V = [IOSObjectArray newArrayWithLength:N type:IOSClass_intArray(1)];
  @try {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(B, BOff, X, 0, BCount);
    for (jint i = 0; i < N; ++i) {
      (void) IOSObjectArray_Set(V, i, LibOrgBouncycastleUtilArrays_cloneWithIntArray_(X));
      LibOrgBouncycastleCryptoGeneratorsSCrypt_BlockMixWithIntArray_withIntArray_withIntArray_withIntArray_withInt_(X, blockX1, blockX2, blockY, r);
    }
    jint mask = N - 1;
    for (jint i = 0; i < N; ++i) {
      jint j = IOSIntArray_Get(X, BCount - 16) & mask;
      LibOrgBouncycastleCryptoGeneratorsSCrypt_XorWithIntArray_withIntArray_withInt_withIntArray_(X, IOSObjectArray_Get(V, j), 0, X);
      LibOrgBouncycastleCryptoGeneratorsSCrypt_BlockMixWithIntArray_withIntArray_withIntArray_withIntArray_withInt_(X, blockX1, blockX2, blockY, r);
    }
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(X, 0, B, BOff, BCount);
  }
  @finally {
    LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearAllWithIntArray2_(V);
    LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearAllWithIntArray2_([IOSObjectArray newArrayWithObjects:(id[]){ X, blockX1, blockX2, blockY } count:4 type:IOSClass_intArray(1)]);
  }
}

void LibOrgBouncycastleCryptoGeneratorsSCrypt_BlockMixWithIntArray_withIntArray_withIntArray_withIntArray_withInt_(IOSIntArray *B, IOSIntArray *X1, IOSIntArray *X2, IOSIntArray *Y, jint r) {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_initialize();
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(B, ((IOSIntArray *) nil_chk(B))->size_ - 16, X1, 0, 16);
  jint BOff = 0;
  jint YOff = 0;
  jint halfLen = JreURShift32(B->size_, 1);
  for (jint i = 2 * r; i > 0; --i) {
    LibOrgBouncycastleCryptoGeneratorsSCrypt_XorWithIntArray_withIntArray_withInt_withIntArray_(X1, B, BOff, X2);
    LibOrgBouncycastleCryptoEnginesSalsa20Engine_salsaCoreWithInt_withIntArray_withIntArray_(8, X2, X1);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(X1, 0, Y, YOff, 16);
    YOff = halfLen + BOff - YOff;
    BOff += 16;
  }
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(Y, 0, B, 0, ((IOSIntArray *) nil_chk(Y))->size_);
}

void LibOrgBouncycastleCryptoGeneratorsSCrypt_XorWithIntArray_withIntArray_withInt_withIntArray_(IOSIntArray *a, IOSIntArray *b, jint bOff, IOSIntArray *output) {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_initialize();
  for (jint i = ((IOSIntArray *) nil_chk(output))->size_ - 1; i >= 0; --i) {
    *IOSIntArray_GetRef(output, i) = IOSIntArray_Get(nil_chk(a), i) ^ IOSIntArray_Get(nil_chk(b), bOff + i);
  }
}

void LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearWithByteArray_(IOSByteArray *array) {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_initialize();
  if (array != nil) {
    LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(array, (jbyte) 0);
  }
}

void LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearWithIntArray_(IOSIntArray *array) {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_initialize();
  if (array != nil) {
    LibOrgBouncycastleUtilArrays_fillWithIntArray_withInt_(array, 0);
  }
}

void LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearAllWithIntArray2_(IOSObjectArray *arrays) {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_initialize();
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(arrays))->size_; ++i) {
    LibOrgBouncycastleCryptoGeneratorsSCrypt_ClearWithIntArray_(IOSObjectArray_Get(arrays, i));
  }
}

jboolean LibOrgBouncycastleCryptoGeneratorsSCrypt_isPowerOf2WithInt_(jint x) {
  LibOrgBouncycastleCryptoGeneratorsSCrypt_initialize();
  return (x & (x - 1)) == 0;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsSCrypt)
