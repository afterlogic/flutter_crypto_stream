//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/XMSSPublicKeyParameters.java
//

#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "XMSSKeyParameters.h"
#include "XMSSParameters.h"
#include "XMSSPublicKeyParameters.h"
#include "XMSSUtil.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/NullPointerException.h"

@interface LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters () {
 @public
  LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params_;
  IOSByteArray *root_;
  IOSByteArray *publicSeed_;
}

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder:(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)builder;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters, params_, LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters, root_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters, publicSeed_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *self, LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder);

__attribute__((unused)) static LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *new_LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *create_LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder);

@interface LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder () {
 @public
  LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params_;
  IOSByteArray *root_;
  IOSByteArray *publicSeed_;
  IOSByteArray *publicKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, params_, LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, root_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, publicSeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, publicKey_, IOSByteArray *)

@implementation LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder:(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)builder {
  LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(self, builder);
  return self;
}

- (IOSByteArray *)toByteArray {
  jint n = [((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk(params_)) getDigestSize];
  jint rootSize = n;
  jint publicSeedSize = n;
  jint totalSize = rootSize + publicSeedSize;
  IOSByteArray *out = [IOSByteArray newArrayWithLength:totalSize];
  jint position = 0;
  LibOrgBouncycastlePqcCryptoXmssXMSSUtil_copyBytesAtOffsetWithByteArray_withByteArray_withInt_(out, root_, position);
  position += rootSize;
  LibOrgBouncycastlePqcCryptoXmssXMSSUtil_copyBytesAtOffsetWithByteArray_withByteArray_withInt_(out, publicSeed_, position);
  return out;
}

- (IOSByteArray *)getRoot {
  return LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(root_);
}

- (IOSByteArray *)getPublicSeed {
  return LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(publicSeed_);
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)getParameters {
  return params_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder:);
  methods[1].selector = @selector(toByteArray);
  methods[2].selector = @selector(getRoot);
  methods[3].selector = @selector(getPublicSeed);
  methods[4].selector = @selector(getParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastlePqcCryptoXmssXMSSParameters;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "root_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "publicSeed_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters = { "XMSSPublicKeyParameters", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x11, 5, 3, -1, 0, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters;
}

@end

void LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *self, LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder) {
  LibOrgBouncycastlePqcCryptoXmssXMSSKeyParameters_initWithBoolean_withNSString_(self, false, [((id<LibOrgBouncycastleCryptoDigest>) nil_chk([((LibOrgBouncycastlePqcCryptoXmssXMSSParameters *) nil_chk(((LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *) nil_chk(builder))->params_)) getDigest])) getAlgorithmName]);
  self->params_ = builder->params_;
  if (self->params_ == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"params == null");
  }
  jint n = [self->params_ getDigestSize];
  IOSByteArray *publicKey = builder->publicKey_;
  if (publicKey != nil) {
    jint rootSize = n;
    jint publicSeedSize = n;
    jint totalSize = rootSize + publicSeedSize;
    if (publicKey->size_ != totalSize) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"public key has wrong size");
    }
    jint position = 0;
    self->root_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(publicKey, position, rootSize);
    position += rootSize;
    self->publicSeed_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_extractBytesAtOffsetWithByteArray_withInt_withInt_(publicKey, position, publicSeedSize);
  }
  else {
    IOSByteArray *tmpRoot = builder->root_;
    if (tmpRoot != nil) {
      if (tmpRoot->size_ != n) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"length of root must be equal to length of digest");
      }
      self->root_ = tmpRoot;
    }
    else {
      self->root_ = [IOSByteArray newArrayWithLength:n];
    }
    IOSByteArray *tmpPublicSeed = builder->publicSeed_;
    if (tmpPublicSeed != nil) {
      if (tmpPublicSeed->size_ != n) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"length of publicSeed must be equal to length of digest");
      }
      self->publicSeed_ = tmpPublicSeed;
    }
    else {
      self->publicSeed_ = [IOSByteArray newArrayWithLength:n];
    }
  }
}

LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *new_LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters, initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_, builder)
}

LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *create_LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *builder) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters, initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_, builder)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters)

@implementation LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters:(LibOrgBouncycastlePqcCryptoXmssXMSSParameters *)params {
  LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(self, params);
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)withRootWithByteArray:(IOSByteArray *)val {
  root_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(val);
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)withPublicSeedWithByteArray:(IOSByteArray *)val {
  publicSeed_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(val);
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *)withPublicKeyWithByteArray:(IOSByteArray *)val {
  publicKey_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray_(val);
  return self;
}

- (LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters *)build {
  return new_LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_initWithLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder;", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder;", 0x1, 3, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder;", 0x1, 4, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters:);
  methods[1].selector = @selector(withRootWithByteArray:);
  methods[2].selector = @selector(withPublicSeedWithByteArray:);
  methods[3].selector = @selector(withPublicKeyWithByteArray:);
  methods[4].selector = @selector(build);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastlePqcCryptoXmssXMSSParameters;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "root_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicSeed_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicKey_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcCryptoXmssXMSSParameters;", "withRoot", "[B", "withPublicSeed", "withPublicKey", "LLibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder = { "Builder", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x9, 5, 4, 5, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder;
}

@end

void LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *self, LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params) {
  NSObject_init(self);
  self->root_ = nil;
  self->publicSeed_ = nil;
  self->publicKey_ = nil;
  self->params_ = params;
}

LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *new_LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_, params)
}

LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder *create_LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder_initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_(LibOrgBouncycastlePqcCryptoXmssXMSSParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder, initWithLibOrgBouncycastlePqcCryptoXmssXMSSParameters_, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssXMSSPublicKeyParameters_Builder)
