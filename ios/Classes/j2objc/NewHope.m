//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/newhope/NewHope.java
//

#include "ErrorCorrection.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NewHope.h"
#include "Params.h"
#include "Poly.h"
#include "SHA3Digest.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"

inline jboolean LibOrgBouncycastlePqcCryptoNewhopeNewHope_get_STATISTICAL_TEST(void);
#define LibOrgBouncycastlePqcCryptoNewhopeNewHope_STATISTICAL_TEST false
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoNewhopeNewHope, STATISTICAL_TEST, jboolean)

@implementation LibOrgBouncycastlePqcCryptoNewhopeNewHope

+ (jint)AGREEMENT_SIZE {
  return LibOrgBouncycastlePqcCryptoNewhopeNewHope_AGREEMENT_SIZE;
}

+ (jint)POLY_SIZE {
  return LibOrgBouncycastlePqcCryptoNewhopeNewHope_POLY_SIZE;
}

+ (jint)SENDA_BYTES {
  return LibOrgBouncycastlePqcCryptoNewhopeNewHope_SENDA_BYTES;
}

+ (jint)SENDB_BYTES {
  return LibOrgBouncycastlePqcCryptoNewhopeNewHope_SENDB_BYTES;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (void)keygenWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)rand
                             withByteArray:(IOSByteArray *)send
                            withShortArray:(IOSShortArray *)sk {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_keygenWithJavaSecuritySecureRandom_withByteArray_withShortArray_(rand, send, sk);
}

+ (void)sharedBWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)rand
                              withByteArray:(IOSByteArray *)sharedKey
                              withByteArray:(IOSByteArray *)send
                              withByteArray:(IOSByteArray *)received {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_sharedBWithJavaSecuritySecureRandom_withByteArray_withByteArray_withByteArray_(rand, sharedKey, send, received);
}

+ (void)sharedAWithByteArray:(IOSByteArray *)sharedKey
              withShortArray:(IOSShortArray *)sk
               withByteArray:(IOSByteArray *)received {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_sharedAWithByteArray_withShortArray_withByteArray_(sharedKey, sk, received);
}

+ (void)decodeAWithShortArray:(IOSShortArray *)pk
                withByteArray:(IOSByteArray *)seed
                withByteArray:(IOSByteArray *)r {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_decodeAWithShortArray_withByteArray_withByteArray_(pk, seed, r);
}

+ (void)decodeBWithShortArray:(IOSShortArray *)b
               withShortArray:(IOSShortArray *)c
                withByteArray:(IOSByteArray *)r {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_decodeBWithShortArray_withShortArray_withByteArray_(b, c, r);
}

+ (void)encodeAWithByteArray:(IOSByteArray *)r
              withShortArray:(IOSShortArray *)pk
               withByteArray:(IOSByteArray *)seed {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_encodeAWithByteArray_withShortArray_withByteArray_(r, pk, seed);
}

+ (void)encodeBWithByteArray:(IOSByteArray *)r
              withShortArray:(IOSShortArray *)b
              withShortArray:(IOSShortArray *)c {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_encodeBWithByteArray_withShortArray_withShortArray_(r, b, c);
}

+ (void)generateAWithShortArray:(IOSShortArray *)a
                  withByteArray:(IOSByteArray *)seed {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_generateAWithShortArray_withByteArray_(a, seed);
}

+ (void)sha3WithByteArray:(IOSByteArray *)sharedKey {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_sha3WithByteArray_(sharedKey);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 8, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 10, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 11, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 13, 14, -1, -1, -1, -1 },
    { NULL, "V", 0x8, 15, 16, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(keygenWithJavaSecuritySecureRandom:withByteArray:withShortArray:);
  methods[2].selector = @selector(sharedBWithJavaSecuritySecureRandom:withByteArray:withByteArray:withByteArray:);
  methods[3].selector = @selector(sharedAWithByteArray:withShortArray:withByteArray:);
  methods[4].selector = @selector(decodeAWithShortArray:withByteArray:withByteArray:);
  methods[5].selector = @selector(decodeBWithShortArray:withShortArray:withByteArray:);
  methods[6].selector = @selector(encodeAWithByteArray:withShortArray:withByteArray:);
  methods[7].selector = @selector(encodeBWithByteArray:withShortArray:withShortArray:);
  methods[8].selector = @selector(generateAWithShortArray:withByteArray:);
  methods[9].selector = @selector(sha3WithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "STATISTICAL_TEST", "Z", .constantValue.asBOOL = LibOrgBouncycastlePqcCryptoNewhopeNewHope_STATISTICAL_TEST, 0x1a, -1, -1, -1, -1 },
    { "AGREEMENT_SIZE", "I", .constantValue.asInt = LibOrgBouncycastlePqcCryptoNewhopeNewHope_AGREEMENT_SIZE, 0x19, -1, -1, -1, -1 },
    { "POLY_SIZE", "I", .constantValue.asInt = LibOrgBouncycastlePqcCryptoNewhopeNewHope_POLY_SIZE, 0x19, -1, -1, -1, -1 },
    { "SENDA_BYTES", "I", .constantValue.asInt = LibOrgBouncycastlePqcCryptoNewhopeNewHope_SENDA_BYTES, 0x19, -1, -1, -1, -1 },
    { "SENDB_BYTES", "I", .constantValue.asInt = LibOrgBouncycastlePqcCryptoNewhopeNewHope_SENDB_BYTES, 0x19, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "keygen", "LJavaSecuritySecureRandom;[B[S", "sharedB", "LJavaSecuritySecureRandom;[B[B[B", "sharedA", "[B[S[B", "decodeA", "[S[B[B", "decodeB", "[S[S[B", "encodeA", "encodeB", "[B[S[S", "generateA", "[S[B", "sha3", "[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoNewhopeNewHope = { "NewHope", "lib.org.bouncycastle.pqc.crypto.newhope", ptrTable, methods, fields, 7, 0x0, 10, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoNewhopeNewHope;
}

@end

void LibOrgBouncycastlePqcCryptoNewhopeNewHope_init(LibOrgBouncycastlePqcCryptoNewhopeNewHope *self) {
  NSObject_init(self);
}

LibOrgBouncycastlePqcCryptoNewhopeNewHope *new_LibOrgBouncycastlePqcCryptoNewhopeNewHope_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNewhopeNewHope, init)
}

LibOrgBouncycastlePqcCryptoNewhopeNewHope *create_LibOrgBouncycastlePqcCryptoNewhopeNewHope_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNewhopeNewHope, init)
}

void LibOrgBouncycastlePqcCryptoNewhopeNewHope_keygenWithJavaSecuritySecureRandom_withByteArray_withShortArray_(JavaSecuritySecureRandom *rand, IOSByteArray *send, IOSShortArray *sk) {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_initialize();
  IOSByteArray *seed = [IOSByteArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_SEED_BYTES];
  [((JavaSecuritySecureRandom *) nil_chk(rand)) nextBytesWithByteArray:seed];
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_sha3WithByteArray_(seed);
  IOSShortArray *a = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_generateAWithShortArray_withByteArray_(a, seed);
  IOSByteArray *noiseSeed = [IOSByteArray newArrayWithLength:32];
  [rand nextBytesWithByteArray:noiseSeed];
  LibOrgBouncycastlePqcCryptoNewhopePoly_getNoiseWithShortArray_withByteArray_withByte_(sk, noiseSeed, (jbyte) 0);
  LibOrgBouncycastlePqcCryptoNewhopePoly_toNTTWithShortArray_(sk);
  IOSShortArray *e = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopePoly_getNoiseWithShortArray_withByteArray_withByte_(e, noiseSeed, (jbyte) 1);
  LibOrgBouncycastlePqcCryptoNewhopePoly_toNTTWithShortArray_(e);
  IOSShortArray *r = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopePoly_pointWiseWithShortArray_withShortArray_withShortArray_(a, sk, r);
  IOSShortArray *pk = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopePoly_addWithShortArray_withShortArray_withShortArray_(r, e, pk);
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_encodeAWithByteArray_withShortArray_withByteArray_(send, pk, seed);
}

void LibOrgBouncycastlePqcCryptoNewhopeNewHope_sharedBWithJavaSecuritySecureRandom_withByteArray_withByteArray_withByteArray_(JavaSecuritySecureRandom *rand, IOSByteArray *sharedKey, IOSByteArray *send, IOSByteArray *received) {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_initialize();
  IOSShortArray *pkA = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  IOSByteArray *seed = [IOSByteArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_SEED_BYTES];
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_decodeAWithShortArray_withByteArray_withByteArray_(pkA, seed, received);
  IOSShortArray *a = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_generateAWithShortArray_withByteArray_(a, seed);
  IOSByteArray *noiseSeed = [IOSByteArray newArrayWithLength:32];
  [((JavaSecuritySecureRandom *) nil_chk(rand)) nextBytesWithByteArray:noiseSeed];
  IOSShortArray *sp = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopePoly_getNoiseWithShortArray_withByteArray_withByte_(sp, noiseSeed, (jbyte) 0);
  LibOrgBouncycastlePqcCryptoNewhopePoly_toNTTWithShortArray_(sp);
  IOSShortArray *ep = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopePoly_getNoiseWithShortArray_withByteArray_withByte_(ep, noiseSeed, (jbyte) 1);
  LibOrgBouncycastlePqcCryptoNewhopePoly_toNTTWithShortArray_(ep);
  IOSShortArray *bp = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopePoly_pointWiseWithShortArray_withShortArray_withShortArray_(a, sp, bp);
  LibOrgBouncycastlePqcCryptoNewhopePoly_addWithShortArray_withShortArray_withShortArray_(bp, ep, bp);
  IOSShortArray *v = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopePoly_pointWiseWithShortArray_withShortArray_withShortArray_(pkA, sp, v);
  LibOrgBouncycastlePqcCryptoNewhopePoly_fromNTTWithShortArray_(v);
  IOSShortArray *epp = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopePoly_getNoiseWithShortArray_withByteArray_withByte_(epp, noiseSeed, (jbyte) 2);
  LibOrgBouncycastlePqcCryptoNewhopePoly_addWithShortArray_withShortArray_withShortArray_(v, epp, v);
  IOSShortArray *c = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_helpRecWithShortArray_withShortArray_withByteArray_withByte_(c, v, noiseSeed, (jbyte) 3);
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_encodeBWithByteArray_withShortArray_withShortArray_(send, bp, c);
  LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_recWithByteArray_withShortArray_withShortArray_(sharedKey, v, c);
  {
    LibOrgBouncycastlePqcCryptoNewhopeNewHope_sha3WithByteArray_(sharedKey);
  }
}

void LibOrgBouncycastlePqcCryptoNewhopeNewHope_sharedAWithByteArray_withShortArray_withByteArray_(IOSByteArray *sharedKey, IOSShortArray *sk, IOSByteArray *received) {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_initialize();
  IOSShortArray *bp = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  IOSShortArray *c = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_decodeBWithShortArray_withShortArray_withByteArray_(bp, c, received);
  IOSShortArray *v = [IOSShortArray newArrayWithLength:LibOrgBouncycastlePqcCryptoNewhopeParams_N];
  LibOrgBouncycastlePqcCryptoNewhopePoly_pointWiseWithShortArray_withShortArray_withShortArray_(sk, bp, v);
  LibOrgBouncycastlePqcCryptoNewhopePoly_fromNTTWithShortArray_(v);
  LibOrgBouncycastlePqcCryptoNewhopeErrorCorrection_recWithByteArray_withShortArray_withShortArray_(sharedKey, v, c);
  {
    LibOrgBouncycastlePqcCryptoNewhopeNewHope_sha3WithByteArray_(sharedKey);
  }
}

void LibOrgBouncycastlePqcCryptoNewhopeNewHope_decodeAWithShortArray_withByteArray_withByteArray_(IOSShortArray *pk, IOSByteArray *seed, IOSByteArray *r) {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_initialize();
  LibOrgBouncycastlePqcCryptoNewhopePoly_fromBytesWithShortArray_withByteArray_(pk, r);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(r, LibOrgBouncycastlePqcCryptoNewhopeParams_POLY_BYTES, seed, 0, LibOrgBouncycastlePqcCryptoNewhopeParams_SEED_BYTES);
}

void LibOrgBouncycastlePqcCryptoNewhopeNewHope_decodeBWithShortArray_withShortArray_withByteArray_(IOSShortArray *b, IOSShortArray *c, IOSByteArray *r) {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_initialize();
  LibOrgBouncycastlePqcCryptoNewhopePoly_fromBytesWithShortArray_withByteArray_(b, r);
  for (jint i = 0; i < LibOrgBouncycastlePqcCryptoNewhopeParams_N / 4; ++i) {
    jint j = 4 * i;
    jint ri = IOSByteArray_Get(nil_chk(r), LibOrgBouncycastlePqcCryptoNewhopeParams_POLY_BYTES + i) & (jint) 0xFF;
    *IOSShortArray_GetRef(nil_chk(c), j + 0) = (jshort) (ri & (jint) 0x03);
    *IOSShortArray_GetRef(c, j + 1) = (jshort) ((JreURShift32(ri, 2)) & (jint) 0x03);
    *IOSShortArray_GetRef(c, j + 2) = (jshort) ((JreURShift32(ri, 4)) & (jint) 0x03);
    *IOSShortArray_GetRef(c, j + 3) = (jshort) (JreURShift32(ri, 6));
  }
}

void LibOrgBouncycastlePqcCryptoNewhopeNewHope_encodeAWithByteArray_withShortArray_withByteArray_(IOSByteArray *r, IOSShortArray *pk, IOSByteArray *seed) {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_initialize();
  LibOrgBouncycastlePqcCryptoNewhopePoly_toBytesWithByteArray_withShortArray_(r, pk);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(seed, 0, r, LibOrgBouncycastlePqcCryptoNewhopeParams_POLY_BYTES, LibOrgBouncycastlePqcCryptoNewhopeParams_SEED_BYTES);
}

void LibOrgBouncycastlePqcCryptoNewhopeNewHope_encodeBWithByteArray_withShortArray_withShortArray_(IOSByteArray *r, IOSShortArray *b, IOSShortArray *c) {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_initialize();
  LibOrgBouncycastlePqcCryptoNewhopePoly_toBytesWithByteArray_withShortArray_(r, b);
  for (jint i = 0; i < LibOrgBouncycastlePqcCryptoNewhopeParams_N / 4; ++i) {
    jint j = 4 * i;
    *IOSByteArray_GetRef(nil_chk(r), LibOrgBouncycastlePqcCryptoNewhopeParams_POLY_BYTES + i) = (jbyte) (IOSShortArray_Get(nil_chk(c), j) | (JreLShift32(IOSShortArray_Get(c, j + 1), 2)) | (JreLShift32(IOSShortArray_Get(c, j + 2), 4)) | (JreLShift32(IOSShortArray_Get(c, j + 3), 6)));
  }
}

void LibOrgBouncycastlePqcCryptoNewhopeNewHope_generateAWithShortArray_withByteArray_(IOSShortArray *a, IOSByteArray *seed) {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_initialize();
  LibOrgBouncycastlePqcCryptoNewhopePoly_uniformWithShortArray_withByteArray_(a, seed);
}

void LibOrgBouncycastlePqcCryptoNewhopeNewHope_sha3WithByteArray_(IOSByteArray *sharedKey) {
  LibOrgBouncycastlePqcCryptoNewhopeNewHope_initialize();
  LibOrgBouncycastleCryptoDigestsSHA3Digest *d = new_LibOrgBouncycastleCryptoDigestsSHA3Digest_initWithInt_(256);
  [d updateWithByteArray:sharedKey withInt:0 withInt:32];
  [d doFinalWithByteArray:sharedKey withInt:0];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoNewhopeNewHope)
