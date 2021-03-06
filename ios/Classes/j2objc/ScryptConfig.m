//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/util/ScryptConfig.java
//

#include "ASN1ObjectIdentifier.h"
#include "J2ObjC_source.h"
#include "MiscObjectIdentifiers.h"
#include "PBKDFConfig.h"
#include "ScryptConfig.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleCryptoUtilScryptConfig () {
 @public
  jint costParameter_;
  jint blockSize_;
  jint parallelizationParameter_;
  jint saltLength_;
}

- (instancetype)initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder:(LibOrgBouncycastleCryptoUtilScryptConfig_Builder *)builder;

@end

__attribute__((unused)) static void LibOrgBouncycastleCryptoUtilScryptConfig_initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder_(LibOrgBouncycastleCryptoUtilScryptConfig *self, LibOrgBouncycastleCryptoUtilScryptConfig_Builder *builder);

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilScryptConfig *new_LibOrgBouncycastleCryptoUtilScryptConfig_initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder_(LibOrgBouncycastleCryptoUtilScryptConfig_Builder *builder) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilScryptConfig *create_LibOrgBouncycastleCryptoUtilScryptConfig_initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder_(LibOrgBouncycastleCryptoUtilScryptConfig_Builder *builder);

@interface LibOrgBouncycastleCryptoUtilScryptConfig_Builder () {
 @public
  jint costParameter_;
  jint blockSize_;
  jint parallelizationParameter_;
  jint saltLength_;
}

+ (jboolean)isPowerOf2WithInt:(jint)x;

@end

__attribute__((unused)) static jboolean LibOrgBouncycastleCryptoUtilScryptConfig_Builder_isPowerOf2WithInt_(jint x);

@implementation LibOrgBouncycastleCryptoUtilScryptConfig

- (instancetype)initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder:(LibOrgBouncycastleCryptoUtilScryptConfig_Builder *)builder {
  LibOrgBouncycastleCryptoUtilScryptConfig_initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder_(self, builder);
  return self;
}

- (jint)getCostParameter {
  return costParameter_;
}

- (jint)getBlockSize {
  return blockSize_;
}

- (jint)getParallelizationParameter {
  return parallelizationParameter_;
}

- (jint)getSaltLength {
  return saltLength_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder:);
  methods[1].selector = @selector(getCostParameter);
  methods[2].selector = @selector(getBlockSize);
  methods[3].selector = @selector(getParallelizationParameter);
  methods[4].selector = @selector(getSaltLength);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "costParameter_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "blockSize_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "parallelizationParameter_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "saltLength_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoUtilScryptConfig_Builder;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoUtilScryptConfig = { "ScryptConfig", "lib.org.bouncycastle.crypto.util", ptrTable, methods, fields, 7, 0x1, 5, 4, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoUtilScryptConfig;
}

@end

void LibOrgBouncycastleCryptoUtilScryptConfig_initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder_(LibOrgBouncycastleCryptoUtilScryptConfig *self, LibOrgBouncycastleCryptoUtilScryptConfig_Builder *builder) {
  LibOrgBouncycastleCryptoUtilPBKDFConfig_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, JreLoadStatic(LibOrgBouncycastleAsn1MiscMiscObjectIdentifiers, id_scrypt));
  self->costParameter_ = ((LibOrgBouncycastleCryptoUtilScryptConfig_Builder *) nil_chk(builder))->costParameter_;
  self->blockSize_ = builder->blockSize_;
  self->parallelizationParameter_ = builder->parallelizationParameter_;
  self->saltLength_ = builder->saltLength_;
}

LibOrgBouncycastleCryptoUtilScryptConfig *new_LibOrgBouncycastleCryptoUtilScryptConfig_initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder_(LibOrgBouncycastleCryptoUtilScryptConfig_Builder *builder) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoUtilScryptConfig, initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder_, builder)
}

LibOrgBouncycastleCryptoUtilScryptConfig *create_LibOrgBouncycastleCryptoUtilScryptConfig_initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder_(LibOrgBouncycastleCryptoUtilScryptConfig_Builder *builder) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoUtilScryptConfig, initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder_, builder)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoUtilScryptConfig)

@implementation LibOrgBouncycastleCryptoUtilScryptConfig_Builder

- (instancetype)initWithInt:(jint)costParameter
                    withInt:(jint)blockSize
                    withInt:(jint)parallelizationParameter {
  LibOrgBouncycastleCryptoUtilScryptConfig_Builder_initWithInt_withInt_withInt_(self, costParameter, blockSize, parallelizationParameter);
  return self;
}

- (LibOrgBouncycastleCryptoUtilScryptConfig_Builder *)withSaltLengthWithInt:(jint)saltLength {
  self->saltLength_ = saltLength;
  return self;
}

- (LibOrgBouncycastleCryptoUtilScryptConfig *)build {
  return new_LibOrgBouncycastleCryptoUtilScryptConfig_initWithLibOrgBouncycastleCryptoUtilScryptConfig_Builder_(self);
}

+ (jboolean)isPowerOf2WithInt:(jint)x {
  return LibOrgBouncycastleCryptoUtilScryptConfig_Builder_isPowerOf2WithInt_(x);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoUtilScryptConfig_Builder;", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoUtilScryptConfig;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0xa, 3, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withInt:withInt:);
  methods[1].selector = @selector(withSaltLengthWithInt:);
  methods[2].selector = @selector(build);
  methods[3].selector = @selector(isPowerOf2WithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "costParameter_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "blockSize_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "parallelizationParameter_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "saltLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "III", "withSaltLength", "I", "isPowerOf2", "LLibOrgBouncycastleCryptoUtilScryptConfig;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoUtilScryptConfig_Builder = { "Builder", "lib.org.bouncycastle.crypto.util", ptrTable, methods, fields, 7, 0x9, 4, 4, 4, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoUtilScryptConfig_Builder;
}

@end

void LibOrgBouncycastleCryptoUtilScryptConfig_Builder_initWithInt_withInt_withInt_(LibOrgBouncycastleCryptoUtilScryptConfig_Builder *self, jint costParameter, jint blockSize, jint parallelizationParameter) {
  NSObject_init(self);
  self->saltLength_ = 16;
  if (costParameter <= 1 || !LibOrgBouncycastleCryptoUtilScryptConfig_Builder_isPowerOf2WithInt_(costParameter)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Cost parameter N must be > 1 and a power of 2");
  }
  self->costParameter_ = costParameter;
  self->blockSize_ = blockSize;
  self->parallelizationParameter_ = parallelizationParameter;
}

LibOrgBouncycastleCryptoUtilScryptConfig_Builder *new_LibOrgBouncycastleCryptoUtilScryptConfig_Builder_initWithInt_withInt_withInt_(jint costParameter, jint blockSize, jint parallelizationParameter) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoUtilScryptConfig_Builder, initWithInt_withInt_withInt_, costParameter, blockSize, parallelizationParameter)
}

LibOrgBouncycastleCryptoUtilScryptConfig_Builder *create_LibOrgBouncycastleCryptoUtilScryptConfig_Builder_initWithInt_withInt_withInt_(jint costParameter, jint blockSize, jint parallelizationParameter) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoUtilScryptConfig_Builder, initWithInt_withInt_withInt_, costParameter, blockSize, parallelizationParameter)
}

jboolean LibOrgBouncycastleCryptoUtilScryptConfig_Builder_isPowerOf2WithInt_(jint x) {
  LibOrgBouncycastleCryptoUtilScryptConfig_Builder_initialize();
  return (x & (x - 1)) == 0;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoUtilScryptConfig_Builder)
