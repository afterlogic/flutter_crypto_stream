//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/PKCS5S2ParametersGenerator.java
//

#include "Arrays.h"
#include "CipherParameters.h"
#include "Digest.h"
#include "DigestFactory.h"
#include "HMac.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "Mac.h"
#include "PBEParametersGenerator.h"
#include "PKCS5S2ParametersGenerator.h"
#include "ParametersWithIV.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator () {
 @public
  id<LibOrgBouncycastleCryptoMac> hMac_;
  IOSByteArray *state_;
}

- (void)FWithByteArray:(IOSByteArray *)S
               withInt:(jint)c
         withByteArray:(IOSByteArray *)iBuf
         withByteArray:(IOSByteArray *)outArg
               withInt:(jint)outOff;

- (IOSByteArray *)generateDerivedKeyWithInt:(jint)dkLen;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator, hMac_, id<LibOrgBouncycastleCryptoMac>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator, state_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_FWithByteArray_withInt_withByteArray_withByteArray_withInt_(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *self, IOSByteArray *S, jint c, IOSByteArray *iBuf, IOSByteArray *outArg, jint outOff);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_generateDerivedKeyWithInt_(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *self, jint dkLen);

@implementation LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest {
  LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(self, digest);
  return self;
}

- (void)FWithByteArray:(IOSByteArray *)S
               withInt:(jint)c
         withByteArray:(IOSByteArray *)iBuf
         withByteArray:(IOSByteArray *)outArg
               withInt:(jint)outOff {
  LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_FWithByteArray_withInt_withByteArray_withByteArray_withInt_(self, S, c, iBuf, outArg, outOff);
}

- (IOSByteArray *)generateDerivedKeyWithInt:(jint)dkLen {
  return LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_generateDerivedKeyWithInt_(self, dkLen);
}

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize {
  keySize = keySize / 8;
  IOSByteArray *dKey = LibOrgBouncycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_generateDerivedKeyWithInt_(self, keySize), 0, keySize);
  return new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_withInt_withInt_(dKey, 0, keySize);
}

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize
                                                                         withInt:(jint)ivSize {
  keySize = keySize / 8;
  ivSize = ivSize / 8;
  IOSByteArray *dKey = LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_generateDerivedKeyWithInt_(self, keySize + ivSize);
  return new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_withInt_withInt_(new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_withInt_withInt_(dKey, 0, keySize), dKey, keySize, ivSize);
}

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedMacParametersWithInt:(jint)keySize {
  return [self generateDerivedParametersWithInt:keySize];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 1, 2, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x1, 5, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x1, 7, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoDigest:);
  methods[2].selector = @selector(FWithByteArray:withInt:withByteArray:withByteArray:withInt:);
  methods[3].selector = @selector(generateDerivedKeyWithInt:);
  methods[4].selector = @selector(generateDerivedParametersWithInt:);
  methods[5].selector = @selector(generateDerivedParametersWithInt:withInt:);
  methods[6].selector = @selector(generateDerivedMacParametersWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "hMac_", "LLibOrgBouncycastleCryptoMac;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "state_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigest;", "F", "[BI[B[BI", "generateDerivedKey", "I", "generateDerivedParameters", "II", "generateDerivedMacParameters" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator = { "PKCS5S2ParametersGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator;
}

@end

void LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_init(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *self) {
  LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(self, LibOrgBouncycastleCryptoUtilDigestFactory_createSHA1());
}

LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *new_LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator, init)
}

LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *create_LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator, init)
}

void LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *self, id<LibOrgBouncycastleCryptoDigest> digest) {
  LibOrgBouncycastleCryptoPBEParametersGenerator_init(self);
  self->hMac_ = new_LibOrgBouncycastleCryptoMacsHMac_initWithLibOrgBouncycastleCryptoDigest_(digest);
  self->state_ = [IOSByteArray newArrayWithLength:[self->hMac_ getMacSize]];
}

LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *new_LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator, initWithLibOrgBouncycastleCryptoDigest_, digest)
}

LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *create_LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator, initWithLibOrgBouncycastleCryptoDigest_, digest)
}

void LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_FWithByteArray_withInt_withByteArray_withByteArray_withInt_(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *self, IOSByteArray *S, jint c, IOSByteArray *iBuf, IOSByteArray *outArg, jint outOff) {
  if (c == 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"iteration count must be at least 1.");
  }
  if (S != nil) {
    [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->hMac_)) updateWithByteArray:S withInt:0 withInt:S->size_];
  }
  [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->hMac_)) updateWithByteArray:iBuf withInt:0 withInt:((IOSByteArray *) nil_chk(iBuf))->size_];
  [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->hMac_)) doFinalWithByteArray:self->state_ withInt:0];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->state_, 0, outArg, outOff, ((IOSByteArray *) nil_chk(self->state_))->size_);
  for (jint count = 1; count < c; count++) {
    [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->hMac_)) updateWithByteArray:self->state_ withInt:0 withInt:((IOSByteArray *) nil_chk(self->state_))->size_];
    [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->hMac_)) doFinalWithByteArray:self->state_ withInt:0];
    for (jint j = 0; j != ((IOSByteArray *) nil_chk(self->state_))->size_; j++) {
      *IOSByteArray_GetRef(nil_chk(outArg), outOff + j) ^= IOSByteArray_Get(self->state_, j);
    }
  }
}

IOSByteArray *LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_generateDerivedKeyWithInt_(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator *self, jint dkLen) {
  jint hLen = [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->hMac_)) getMacSize];
  jint l = (dkLen + hLen - 1) / hLen;
  IOSByteArray *iBuf = [IOSByteArray newArrayWithLength:4];
  IOSByteArray *outBytes = [IOSByteArray newArrayWithLength:l * hLen];
  jint outPos = 0;
  id<LibOrgBouncycastleCryptoCipherParameters> param = new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_(self->password_);
  [((id<LibOrgBouncycastleCryptoMac>) nil_chk(self->hMac_)) init__WithLibOrgBouncycastleCryptoCipherParameters:param];
  for (jint i = 1; i <= l; i++) {
    jint pos = 3;
    while (++(*IOSByteArray_GetRef(iBuf, pos)) == 0) {
      --pos;
    }
    LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator_FWithByteArray_withInt_withByteArray_withByteArray_withInt_(self, self->salt_, self->iterationCount_, iBuf, outBytes, outPos);
    outPos += hLen;
  }
  return outBytes;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsPKCS5S2ParametersGenerator)