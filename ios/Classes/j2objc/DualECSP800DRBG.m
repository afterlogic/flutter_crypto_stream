//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/prng/drbg/DualECSP800DRBG.java
//

#include "Arrays.h"
#include "BigIntegers.h"
#include "CryptoPrngDrbgUtils.h"
#include "Digest.h"
#include "DualECPoints.h"
#include "DualECSP800DRBG.h"
#include "ECCurve.h"
#include "ECFieldElement.h"
#include "ECMultiplier.h"
#include "ECPoint.h"
#include "EntropySource.h"
#include "FixedPointCombMultiplier.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NISTNamedCurves.h"
#include "X9ECParameters.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG () {
 @public
  id<LibOrgBouncycastleCryptoDigest> _digest_;
  jlong _reseedCounter_;
  id<LibOrgBouncycastleCryptoPrngEntropySource> _entropySource_;
  jint _securityStrength_;
  jint _seedlen_;
  jint _outlen_;
  LibOrgBouncycastleMathEcECCurve_Fp *_curve_;
  LibOrgBouncycastleMathEcECPoint *_P_;
  LibOrgBouncycastleMathEcECPoint *_Q_;
  IOSByteArray *_s_;
  jint _sLength_;
  id<LibOrgBouncycastleMathEcECMultiplier> _fixedPointMultiplier_;
}

- (IOSByteArray *)getEntropy;

- (IOSByteArray *)xor__WithByteArray:(IOSByteArray *)a
                       withByteArray:(IOSByteArray *)b;

- (IOSByteArray *)pad8WithByteArray:(IOSByteArray *)s
                            withInt:(jint)seedlen;

- (JavaMathBigInteger *)getScalarMultipleXCoordWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                            withJavaMathBigInteger:(JavaMathBigInteger *)s;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, _digest_, id<LibOrgBouncycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, _entropySource_, id<LibOrgBouncycastleCryptoPrngEntropySource>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, _curve_, LibOrgBouncycastleMathEcECCurve_Fp *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, _P_, LibOrgBouncycastleMathEcECPoint *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, _Q_, LibOrgBouncycastleMathEcECPoint *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, _s_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, _fixedPointMultiplier_, id<LibOrgBouncycastleMathEcECMultiplier>)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p256_Px(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Px;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p256_Px, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p256_Py(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Py;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p256_Py, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p256_Qx(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qx;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p256_Qx, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p256_Qy(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qy;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p256_Qy, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p384_Px(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Px;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p384_Px, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p384_Py(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Py;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p384_Py, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p384_Qx(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qx;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p384_Qx, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p384_Qy(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qy;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p384_Qy, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p521_Px(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Px;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p521_Px, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p521_Py(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Py;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p521_Py, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p521_Qx(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qx;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p521_Qx, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_p521_Qy(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qy;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, p521_Qy, JavaMathBigInteger *)

inline IOSObjectArray *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_nistPoints(void);
static IOSObjectArray *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, nistPoints, IOSObjectArray *)

inline jlong LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_RESEED_MAX(void);
#define LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_RESEED_MAX 2147483648LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, RESEED_MAX, jlong)

inline jint LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_MAX_ADDITIONAL_INPUT(void);
#define LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ADDITIONAL_INPUT 4096
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, MAX_ADDITIONAL_INPUT, jint)

inline jint LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_MAX_ENTROPY_LENGTH(void);
#define LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ENTROPY_LENGTH 4096
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, MAX_ENTROPY_LENGTH, jint)

inline jint LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_get_MAX_PERSONALIZATION_STRING(void);
#define LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_MAX_PERSONALIZATION_STRING 4096
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, MAX_PERSONALIZATION_STRING, jint)

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getEntropy(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *self);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_xor__WithByteArray_withByteArray_(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *self, IOSByteArray *a, IOSByteArray *b);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_pad8WithByteArray_withInt_(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *self, IOSByteArray *s, jint seedlen);

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *self, LibOrgBouncycastleMathEcECPoint *p, JavaMathBigInteger *s);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG)

@implementation LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG

- (instancetype)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                               withInt:(jint)securityStrength
         withLibOrgBouncycastleCryptoPrngEntropySource:(id<LibOrgBouncycastleCryptoPrngEntropySource>)entropySource
                                         withByteArray:(IOSByteArray *)personalizationString
                                         withByteArray:(IOSByteArray *)nonce {
  LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_initWithLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(self, digest, securityStrength, entropySource, personalizationString, nonce);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoPrngDrbgDualECPointsArray:(IOSObjectArray *)pointSet
                                       withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
                                                                  withInt:(jint)securityStrength
                            withLibOrgBouncycastleCryptoPrngEntropySource:(id<LibOrgBouncycastleCryptoPrngEntropySource>)entropySource
                                                            withByteArray:(IOSByteArray *)personalizationString
                                                            withByteArray:(IOSByteArray *)nonce {
  LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_initWithLibOrgBouncycastleCryptoPrngDrbgDualECPointsArray_withLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(self, pointSet, digest, securityStrength, entropySource, personalizationString, nonce);
  return self;
}

- (jint)getBlockSize {
  return _outlen_ * 8;
}

- (jint)generateWithByteArray:(IOSByteArray *)output
                withByteArray:(IOSByteArray *)additionalInput
                  withBoolean:(jboolean)predictionResistant {
  jint numberOfBits = ((IOSByteArray *) nil_chk(output))->size_ * 8;
  jint m = output->size_ / _outlen_;
  if (LibOrgBouncycastleCryptoPrngDrbgCryptoPrngDrbgUtils_isTooLargeWithByteArray_withInt_(additionalInput, LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ADDITIONAL_INPUT / 8)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Additional input too large");
  }
  if (_reseedCounter_ + m > LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_RESEED_MAX) {
    return -1;
  }
  if (predictionResistant) {
    [self reseedWithByteArray:additionalInput];
    additionalInput = nil;
  }
  JavaMathBigInteger *s;
  if (additionalInput != nil) {
    additionalInput = LibOrgBouncycastleCryptoPrngDrbgCryptoPrngDrbgUtils_hash_dfWithLibOrgBouncycastleCryptoDigest_withByteArray_withInt_(_digest_, additionalInput, _seedlen_);
    s = new_JavaMathBigInteger_initWithInt_withByteArray_(1, LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_xor__WithByteArray_withByteArray_(self, _s_, additionalInput));
  }
  else {
    s = new_JavaMathBigInteger_initWithInt_withByteArray_(1, _s_);
  }
  LibOrgBouncycastleUtilArrays_fillWithByteArray_withByte_(output, (jbyte) 0);
  jint outOffset = 0;
  for (jint i = 0; i < m; i++) {
    s = LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(self, _P_, s);
    IOSByteArray *r = [((JavaMathBigInteger *) nil_chk(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(self, _Q_, s))) toByteArray];
    if (((IOSByteArray *) nil_chk(r))->size_ > _outlen_) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(r, r->size_ - _outlen_, output, outOffset, _outlen_);
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(r, 0, output, outOffset + (_outlen_ - r->size_), r->size_);
    }
    outOffset += _outlen_;
    _reseedCounter_++;
  }
  if (outOffset < output->size_) {
    s = LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(self, _P_, s);
    IOSByteArray *r = [((JavaMathBigInteger *) nil_chk(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(self, _Q_, s))) toByteArray];
    jint required = output->size_ - outOffset;
    if (((IOSByteArray *) nil_chk(r))->size_ > _outlen_) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(r, r->size_ - _outlen_, output, outOffset, required);
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(r, 0, output, outOffset + (_outlen_ - r->size_), required);
    }
    _reseedCounter_++;
  }
  _s_ = LibOrgBouncycastleUtilBigIntegers_asUnsignedByteArrayWithInt_withJavaMathBigInteger_(_sLength_, LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(self, _P_, s));
  return numberOfBits;
}

- (void)reseedWithByteArray:(IOSByteArray *)additionalInput {
  if (LibOrgBouncycastleCryptoPrngDrbgCryptoPrngDrbgUtils_isTooLargeWithByteArray_withInt_(additionalInput, LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ADDITIONAL_INPUT / 8)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Additional input string too large");
  }
  IOSByteArray *entropy = LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getEntropy(self);
  IOSByteArray *seedMaterial = LibOrgBouncycastleUtilArrays_concatenateWithByteArray_withByteArray_withByteArray_(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_pad8WithByteArray_withInt_(self, _s_, _seedlen_), entropy, additionalInput);
  _s_ = LibOrgBouncycastleCryptoPrngDrbgCryptoPrngDrbgUtils_hash_dfWithLibOrgBouncycastleCryptoDigest_withByteArray_withInt_(_digest_, seedMaterial, _seedlen_);
  _reseedCounter_ = 0;
}

- (IOSByteArray *)getEntropy {
  return LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getEntropy(self);
}

- (IOSByteArray *)xor__WithByteArray:(IOSByteArray *)a
                       withByteArray:(IOSByteArray *)b {
  return LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_xor__WithByteArray_withByteArray_(self, a, b);
}

- (IOSByteArray *)pad8WithByteArray:(IOSByteArray *)s
                            withInt:(jint)seedlen {
  return LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_pad8WithByteArray_withInt_(self, s, seedlen);
}

- (JavaMathBigInteger *)getScalarMultipleXCoordWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                            withJavaMathBigInteger:(JavaMathBigInteger *)s {
  return LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(self, p, s);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 8, 9, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, 10, 11, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoDigest:withInt:withLibOrgBouncycastleCryptoPrngEntropySource:withByteArray:withByteArray:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoPrngDrbgDualECPointsArray:withLibOrgBouncycastleCryptoDigest:withInt:withLibOrgBouncycastleCryptoPrngEntropySource:withByteArray:withByteArray:);
  methods[2].selector = @selector(getBlockSize);
  methods[3].selector = @selector(generateWithByteArray:withByteArray:withBoolean:);
  methods[4].selector = @selector(reseedWithByteArray:);
  methods[5].selector = @selector(getEntropy);
  methods[6].selector = @selector(xor__WithByteArray:withByteArray:);
  methods[7].selector = @selector(pad8WithByteArray:withInt:);
  methods[8].selector = @selector(getScalarMultipleXCoordWithLibOrgBouncycastleMathEcECPoint:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "p256_Px", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 12, -1, -1 },
    { "p256_Py", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 13, -1, -1 },
    { "p256_Qx", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 14, -1, -1 },
    { "p256_Qy", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 15, -1, -1 },
    { "p384_Px", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 16, -1, -1 },
    { "p384_Py", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 17, -1, -1 },
    { "p384_Qx", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 18, -1, -1 },
    { "p384_Qy", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 19, -1, -1 },
    { "p521_Px", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 20, -1, -1 },
    { "p521_Py", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 21, -1, -1 },
    { "p521_Qx", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 22, -1, -1 },
    { "p521_Qy", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 23, -1, -1 },
    { "nistPoints", "[LLibOrgBouncycastleCryptoPrngDrbgDualECPoints;", .constantValue.asLong = 0, 0x1a, -1, 24, -1, -1 },
    { "RESEED_MAX", "J", .constantValue.asLong = LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_RESEED_MAX, 0x1a, -1, -1, -1, -1 },
    { "MAX_ADDITIONAL_INPUT", "I", .constantValue.asInt = LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ADDITIONAL_INPUT, 0x1a, -1, -1, -1, -1 },
    { "MAX_ENTROPY_LENGTH", "I", .constantValue.asInt = LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ENTROPY_LENGTH, 0x1a, -1, -1, -1, -1 },
    { "MAX_PERSONALIZATION_STRING", "I", .constantValue.asInt = LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_MAX_PERSONALIZATION_STRING, 0x1a, -1, -1, -1, -1 },
    { "_digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_reseedCounter_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_entropySource_", "LLibOrgBouncycastleCryptoPrngEntropySource;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_securityStrength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_seedlen_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_outlen_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_curve_", "LLibOrgBouncycastleMathEcECCurve_Fp;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_P_", "LLibOrgBouncycastleMathEcECPoint;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_Q_", "LLibOrgBouncycastleMathEcECPoint;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_s_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_sLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_fixedPointMultiplier_", "LLibOrgBouncycastleMathEcECMultiplier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigest;ILLibOrgBouncycastleCryptoPrngEntropySource;[B[B", "[LLibOrgBouncycastleCryptoPrngDrbgDualECPoints;LLibOrgBouncycastleCryptoDigest;ILLibOrgBouncycastleCryptoPrngEntropySource;[B[B", "generate", "[B[BZ", "reseed", "[B", "xor", "[B[B", "pad8", "[BI", "getScalarMultipleXCoord", "LLibOrgBouncycastleMathEcECPoint;LJavaMathBigInteger;", &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Px, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Py, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qx, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qy, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Px, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Py, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qx, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qy, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Px, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Py, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qx, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qy, &LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG = { "DualECSP800DRBG", "lib.org.bouncycastle.crypto.prng.drbg", ptrTable, methods, fields, 7, 0x1, 9, 29, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG class]) {
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Px = new_JavaMathBigInteger_initWithNSString_withInt_(@"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Py = new_JavaMathBigInteger_initWithNSString_withInt_(@"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qx = new_JavaMathBigInteger_initWithNSString_withInt_(@"c97445f45cdef9f0d3e05e1e585fc297235b82b5be8ff3efca67c59852018192", 16);
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qy = new_JavaMathBigInteger_initWithNSString_withInt_(@"b28ef557ba31dfcbdd21ac46e2a91e3c304f44cb87058ada2cb815151e610046", 16);
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Px = new_JavaMathBigInteger_initWithNSString_withInt_(@"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16);
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Py = new_JavaMathBigInteger_initWithNSString_withInt_(@"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16);
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qx = new_JavaMathBigInteger_initWithNSString_withInt_(@"8e722de3125bddb05580164bfe20b8b432216a62926c57502ceede31c47816edd1e89769124179d0b695106428815065", 16);
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qy = new_JavaMathBigInteger_initWithNSString_withInt_(@"023b1660dd701d0839fd45eec36f9ee7b32e13b315dc02610aa1b636e346df671f790f84c5e09b05674dbb7e45c803dd", 16);
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Px = new_JavaMathBigInteger_initWithNSString_withInt_(@"c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16);
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Py = new_JavaMathBigInteger_initWithNSString_withInt_(@"11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16);
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qx = new_JavaMathBigInteger_initWithNSString_withInt_(@"1b9fa3e518d683c6b65763694ac8efbaec6fab44f2276171a42726507dd08add4c3b3f4c1ebc5b1222ddba077f722943b24c3edfa0f85fe24d0c8c01591f0be6f63", 16);
    LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qy = new_JavaMathBigInteger_initWithNSString_withInt_(@"1f3bdba585295d9a1110d1df1f9430ef8442c5018976ff3437ef91b81dc0b8132c8d5c39c32d0e004a3092b7d327c0e7a4d26d2c7b69b58f9066652911e457779de", 16);
    {
      LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints = [IOSObjectArray newArrayWithLength:3 type:LibOrgBouncycastleCryptoPrngDrbgDualECPoints_class_()];
      LibOrgBouncycastleMathEcECCurve_Fp *curve = (LibOrgBouncycastleMathEcECCurve_Fp *) cast_chk([((LibOrgBouncycastleAsn1X9X9ECParameters *) nil_chk(LibOrgBouncycastleAsn1NistNISTNamedCurves_getByNameWithNSString_(@"P-256"))) getCurve], [LibOrgBouncycastleMathEcECCurve_Fp class]);
      (void) IOSObjectArray_SetAndConsume(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints, 0, new_LibOrgBouncycastleCryptoPrngDrbgDualECPoints_initWithInt_withLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_withInt_(128, [((LibOrgBouncycastleMathEcECCurve_Fp *) nil_chk(curve)) createPointWithJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Px withJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Py], [curve createPointWithJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qx withJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qy], 1));
      curve = (LibOrgBouncycastleMathEcECCurve_Fp *) cast_chk([((LibOrgBouncycastleAsn1X9X9ECParameters *) nil_chk(LibOrgBouncycastleAsn1NistNISTNamedCurves_getByNameWithNSString_(@"P-384"))) getCurve], [LibOrgBouncycastleMathEcECCurve_Fp class]);
      (void) IOSObjectArray_SetAndConsume(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints, 1, new_LibOrgBouncycastleCryptoPrngDrbgDualECPoints_initWithInt_withLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_withInt_(192, [((LibOrgBouncycastleMathEcECCurve_Fp *) nil_chk(curve)) createPointWithJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Px withJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Py], [curve createPointWithJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qx withJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qy], 1));
      curve = (LibOrgBouncycastleMathEcECCurve_Fp *) cast_chk([((LibOrgBouncycastleAsn1X9X9ECParameters *) nil_chk(LibOrgBouncycastleAsn1NistNISTNamedCurves_getByNameWithNSString_(@"P-521"))) getCurve], [LibOrgBouncycastleMathEcECCurve_Fp class]);
      (void) IOSObjectArray_SetAndConsume(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints, 2, new_LibOrgBouncycastleCryptoPrngDrbgDualECPoints_initWithInt_withLibOrgBouncycastleMathEcECPoint_withLibOrgBouncycastleMathEcECPoint_withInt_(256, [((LibOrgBouncycastleMathEcECCurve_Fp *) nil_chk(curve)) createPointWithJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Px withJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Py], [curve createPointWithJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qx withJavaMathBigInteger:LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qy], 1));
    }
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG)
  }
}

@end

void LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_initWithLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *self, id<LibOrgBouncycastleCryptoDigest> digest, jint securityStrength, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_initWithLibOrgBouncycastleCryptoPrngDrbgDualECPointsArray_withLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(self, LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints, digest, securityStrength, entropySource, personalizationString, nonce);
}

LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *new_LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_initWithLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(id<LibOrgBouncycastleCryptoDigest> digest, jint securityStrength, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, initWithLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_, digest, securityStrength, entropySource, personalizationString, nonce)
}

LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *create_LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_initWithLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(id<LibOrgBouncycastleCryptoDigest> digest, jint securityStrength, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, initWithLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_, digest, securityStrength, entropySource, personalizationString, nonce)
}

void LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_initWithLibOrgBouncycastleCryptoPrngDrbgDualECPointsArray_withLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *self, IOSObjectArray *pointSet, id<LibOrgBouncycastleCryptoDigest> digest, jint securityStrength, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  NSObject_init(self);
  self->_fixedPointMultiplier_ = new_LibOrgBouncycastleMathEcFixedPointCombMultiplier_init();
  self->_digest_ = digest;
  self->_entropySource_ = entropySource;
  self->_securityStrength_ = securityStrength;
  if (LibOrgBouncycastleCryptoPrngDrbgCryptoPrngDrbgUtils_isTooLargeWithByteArray_withInt_(personalizationString, LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_MAX_PERSONALIZATION_STRING / 8)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Personalization string too large");
  }
  if ([((id<LibOrgBouncycastleCryptoPrngEntropySource>) nil_chk(entropySource)) entropySize] < securityStrength || [entropySource entropySize] > LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ENTROPY_LENGTH) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I$I$", @"EntropySource must provide between ", securityStrength, @" and ", LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ENTROPY_LENGTH, @" bits"));
  }
  IOSByteArray *entropy = LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getEntropy(self);
  IOSByteArray *seedMaterial = LibOrgBouncycastleUtilArrays_concatenateWithByteArray_withByteArray_withByteArray_(entropy, nonce, personalizationString);
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(pointSet))->size_; i++) {
    if (securityStrength <= [((LibOrgBouncycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getSecurityStrength]) {
      if (LibOrgBouncycastleCryptoPrngDrbgCryptoPrngDrbgUtils_getMaxSecurityStrengthWithLibOrgBouncycastleCryptoDigest_(digest) < [((LibOrgBouncycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getSecurityStrength]) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Requested security strength is not supported by digest");
      }
      self->_seedlen_ = [((LibOrgBouncycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getSeedLen];
      self->_outlen_ = [((LibOrgBouncycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getMaxOutlen] / 8;
      self->_P_ = [((LibOrgBouncycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getP];
      self->_Q_ = [((LibOrgBouncycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getQ];
      break;
    }
  }
  if (self->_P_ == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"security strength cannot be greater than 256 bits");
  }
  self->_s_ = LibOrgBouncycastleCryptoPrngDrbgCryptoPrngDrbgUtils_hash_dfWithLibOrgBouncycastleCryptoDigest_withByteArray_withInt_(self->_digest_, seedMaterial, self->_seedlen_);
  self->_sLength_ = ((IOSByteArray *) nil_chk(self->_s_))->size_;
  self->_reseedCounter_ = 0;
}

LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *new_LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_initWithLibOrgBouncycastleCryptoPrngDrbgDualECPointsArray_withLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(IOSObjectArray *pointSet, id<LibOrgBouncycastleCryptoDigest> digest, jint securityStrength, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, initWithLibOrgBouncycastleCryptoPrngDrbgDualECPointsArray_withLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_, pointSet, digest, securityStrength, entropySource, personalizationString, nonce)
}

LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *create_LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_initWithLibOrgBouncycastleCryptoPrngDrbgDualECPointsArray_withLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_(IOSObjectArray *pointSet, id<LibOrgBouncycastleCryptoDigest> digest, jint securityStrength, id<LibOrgBouncycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG, initWithLibOrgBouncycastleCryptoPrngDrbgDualECPointsArray_withLibOrgBouncycastleCryptoDigest_withInt_withLibOrgBouncycastleCryptoPrngEntropySource_withByteArray_withByteArray_, pointSet, digest, securityStrength, entropySource, personalizationString, nonce)
}

IOSByteArray *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getEntropy(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *self) {
  IOSByteArray *entropy = [((id<LibOrgBouncycastleCryptoPrngEntropySource>) nil_chk(self->_entropySource_)) getEntropy];
  if (((IOSByteArray *) nil_chk(entropy))->size_ < (self->_securityStrength_ + 7) / 8) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Insufficient entropy provided by entropy source");
  }
  return entropy;
}

IOSByteArray *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_xor__WithByteArray_withByteArray_(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *self, IOSByteArray *a, IOSByteArray *b) {
  if (b == nil) {
    return a;
  }
  IOSByteArray *rv = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(a))->size_];
  for (jint i = 0; i != rv->size_; i++) {
    *IOSByteArray_GetRef(rv, i) = (jbyte) (IOSByteArray_Get(a, i) ^ IOSByteArray_Get(b, i));
  }
  return rv;
}

IOSByteArray *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_pad8WithByteArray_withInt_(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *self, IOSByteArray *s, jint seedlen) {
  if (seedlen % 8 == 0) {
    return s;
  }
  jint shift = 8 - (seedlen % 8);
  jint carry = 0;
  for (jint i = ((IOSByteArray *) nil_chk(s))->size_ - 1; i >= 0; i--) {
    jint b = IOSByteArray_Get(s, i) & (jint) 0xff;
    *IOSByteArray_GetRef(s, i) = (jbyte) ((JreLShift32(b, shift)) | (JreRShift32(carry, (8 - shift))));
    carry = b;
  }
  return s;
}

JavaMathBigInteger *LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG *self, LibOrgBouncycastleMathEcECPoint *p, JavaMathBigInteger *s) {
  return [((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk([((id<LibOrgBouncycastleMathEcECMultiplier>) nil_chk(self->_fixedPointMultiplier_)) multiplyWithLibOrgBouncycastleMathEcECPoint:p withJavaMathBigInteger:s])) normalize])) getAffineXCoord])) toBigInteger];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoPrngDrbgDualECSP800DRBG)
