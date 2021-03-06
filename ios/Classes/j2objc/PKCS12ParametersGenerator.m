//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/PKCS12ParametersGenerator.java
//

#include "CipherParameters.h"
#include "Digest.h"
#include "ExtendedDigest.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyParameter.h"
#include "PBEParametersGenerator.h"
#include "PKCS12ParametersGenerator.h"
#include "ParametersWithIV.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator () {
 @public
  id<LibOrgBouncycastleCryptoDigest> digest_;
  jint u_;
  jint v_;
}

- (void)adjustWithByteArray:(IOSByteArray *)a
                    withInt:(jint)aOff
              withByteArray:(IOSByteArray *)b;

- (IOSByteArray *)generateDerivedKeyWithInt:(jint)idByte
                                    withInt:(jint)n;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator, digest_, id<LibOrgBouncycastleCryptoDigest>)

__attribute__((unused)) static void LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_adjustWithByteArray_withInt_withByteArray_(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator *self, IOSByteArray *a, jint aOff, IOSByteArray *b);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_generateDerivedKeyWithInt_withInt_(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator *self, jint idByte, jint n);

@implementation LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator

+ (jint)KEY_MATERIAL {
  return LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_KEY_MATERIAL;
}

+ (jint)IV_MATERIAL {
  return LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_IV_MATERIAL;
}

+ (jint)MAC_MATERIAL {
  return LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_MAC_MATERIAL;
}

- (instancetype)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest {
  LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(self, digest);
  return self;
}

- (void)adjustWithByteArray:(IOSByteArray *)a
                    withInt:(jint)aOff
              withByteArray:(IOSByteArray *)b {
  LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_adjustWithByteArray_withInt_withByteArray_(self, a, aOff, b);
}

- (IOSByteArray *)generateDerivedKeyWithInt:(jint)idByte
                                    withInt:(jint)n {
  return LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_generateDerivedKeyWithInt_withInt_(self, idByte, n);
}

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize {
  keySize = keySize / 8;
  IOSByteArray *dKey = LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_generateDerivedKeyWithInt_withInt_(self, LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_KEY_MATERIAL, keySize);
  return new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_withInt_withInt_(dKey, 0, keySize);
}

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize
                                                                         withInt:(jint)ivSize {
  keySize = keySize / 8;
  ivSize = ivSize / 8;
  IOSByteArray *dKey = LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_generateDerivedKeyWithInt_withInt_(self, LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_KEY_MATERIAL, keySize);
  IOSByteArray *iv = LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_generateDerivedKeyWithInt_withInt_(self, LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_IV_MATERIAL, ivSize);
  return new_LibOrgBouncycastleCryptoParamsParametersWithIV_initWithLibOrgBouncycastleCryptoCipherParameters_withByteArray_withInt_withInt_(new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_withInt_withInt_(dKey, 0, keySize), iv, 0, ivSize);
}

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedMacParametersWithInt:(jint)keySize {
  keySize = keySize / 8;
  IOSByteArray *dKey = LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_generateDerivedKeyWithInt_withInt_(self, LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_MAC_MATERIAL, keySize);
  return new_LibOrgBouncycastleCryptoParamsKeyParameter_initWithByteArray_withInt_withInt_(dKey, 0, keySize);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 1, 2, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x1, 5, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoCipherParameters;", 0x1, 7, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoDigest:);
  methods[1].selector = @selector(adjustWithByteArray:withInt:withByteArray:);
  methods[2].selector = @selector(generateDerivedKeyWithInt:withInt:);
  methods[3].selector = @selector(generateDerivedParametersWithInt:);
  methods[4].selector = @selector(generateDerivedParametersWithInt:withInt:);
  methods[5].selector = @selector(generateDerivedMacParametersWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "KEY_MATERIAL", "I", .constantValue.asInt = LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_KEY_MATERIAL, 0x19, -1, -1, -1, -1 },
    { "IV_MATERIAL", "I", .constantValue.asInt = LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_IV_MATERIAL, 0x19, -1, -1, -1, -1 },
    { "MAC_MATERIAL", "I", .constantValue.asInt = LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_MAC_MATERIAL, 0x19, -1, -1, -1, -1 },
    { "digest_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "u_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "v_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoDigest;", "adjust", "[BI[B", "generateDerivedKey", "II", "generateDerivedParameters", "I", "generateDerivedMacParameters" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator = { "PKCS12ParametersGenerator", "lib.org.bouncycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 6, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator;
}

@end

void LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator *self, id<LibOrgBouncycastleCryptoDigest> digest) {
  LibOrgBouncycastleCryptoPBEParametersGenerator_init(self);
  self->digest_ = digest;
  if ([LibOrgBouncycastleCryptoExtendedDigest_class_() isInstance:digest]) {
    self->u_ = [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest)) getDigestSize];
    self->v_ = [((id<LibOrgBouncycastleCryptoExtendedDigest>) cast_check(digest, LibOrgBouncycastleCryptoExtendedDigest_class_())) getByteLength];
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$$", @"Digest ", [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(digest)) getAlgorithmName], @" unsupported"));
  }
}

LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator *new_LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator, initWithLibOrgBouncycastleCryptoDigest_, digest)
}

LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator *create_LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator, initWithLibOrgBouncycastleCryptoDigest_, digest)
}

void LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_adjustWithByteArray_withInt_withByteArray_(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator *self, IOSByteArray *a, jint aOff, IOSByteArray *b) {
  jint x = (IOSByteArray_Get(b, ((IOSByteArray *) nil_chk(b))->size_ - 1) & (jint) 0xff) + (IOSByteArray_Get(nil_chk(a), aOff + b->size_ - 1) & (jint) 0xff) + 1;
  *IOSByteArray_GetRef(a, aOff + b->size_ - 1) = (jbyte) x;
  JreURShiftAssignInt(&x, 8);
  for (jint i = b->size_ - 2; i >= 0; i--) {
    x += (IOSByteArray_Get(b, i) & (jint) 0xff) + (IOSByteArray_Get(a, aOff + i) & (jint) 0xff);
    *IOSByteArray_GetRef(a, aOff + i) = (jbyte) x;
    JreURShiftAssignInt(&x, 8);
  }
}

IOSByteArray *LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_generateDerivedKeyWithInt_withInt_(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator *self, jint idByte, jint n) {
  IOSByteArray *D = [IOSByteArray newArrayWithLength:self->v_];
  IOSByteArray *dKey = [IOSByteArray newArrayWithLength:n];
  for (jint i = 0; i != D->size_; i++) {
    *IOSByteArray_GetRef(D, i) = (jbyte) idByte;
  }
  IOSByteArray *S;
  if ((self->salt_ != nil) && (((IOSByteArray *) nil_chk(self->salt_))->size_ != 0)) {
    S = [IOSByteArray newArrayWithLength:self->v_ * ((((IOSByteArray *) nil_chk(self->salt_))->size_ + self->v_ - 1) / self->v_)];
    for (jint i = 0; i != S->size_; i++) {
      *IOSByteArray_GetRef(S, i) = IOSByteArray_Get(self->salt_, i % self->salt_->size_);
    }
  }
  else {
    S = [IOSByteArray newArrayWithLength:0];
  }
  IOSByteArray *P;
  if ((self->password_ != nil) && (((IOSByteArray *) nil_chk(self->password_))->size_ != 0)) {
    P = [IOSByteArray newArrayWithLength:self->v_ * ((((IOSByteArray *) nil_chk(self->password_))->size_ + self->v_ - 1) / self->v_)];
    for (jint i = 0; i != P->size_; i++) {
      *IOSByteArray_GetRef(P, i) = IOSByteArray_Get(self->password_, i % self->password_->size_);
    }
  }
  else {
    P = [IOSByteArray newArrayWithLength:0];
  }
  IOSByteArray *I = [IOSByteArray newArrayWithLength:S->size_ + P->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(S, 0, I, 0, S->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(P, 0, I, S->size_, P->size_);
  IOSByteArray *B = [IOSByteArray newArrayWithLength:self->v_];
  jint c = (n + self->u_ - 1) / self->u_;
  IOSByteArray *A = [IOSByteArray newArrayWithLength:self->u_];
  for (jint i = 1; i <= c; i++) {
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->digest_)) updateWithByteArray:D withInt:0 withInt:D->size_];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->digest_)) updateWithByteArray:I withInt:0 withInt:I->size_];
    [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->digest_)) doFinalWithByteArray:A withInt:0];
    for (jint j = 1; j < self->iterationCount_; j++) {
      [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->digest_)) updateWithByteArray:A withInt:0 withInt:A->size_];
      [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->digest_)) doFinalWithByteArray:A withInt:0];
    }
    for (jint j = 0; j != B->size_; j++) {
      *IOSByteArray_GetRef(B, j) = IOSByteArray_Get(A, j % A->size_);
    }
    for (jint j = 0; j != I->size_ / self->v_; j++) {
      LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_adjustWithByteArray_withInt_withByteArray_(self, I, j * self->v_, B);
    }
    if (i == c) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(A, 0, dKey, (i - 1) * self->u_, dKey->size_ - ((i - 1) * self->u_));
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(A, 0, dKey, (i - 1) * self->u_, A->size_);
    }
  }
  return dKey;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator)
