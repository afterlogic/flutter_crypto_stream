//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/generation/KeySpecBuilder.java
//

#include "AlgorithmSuite.h"
#include "CompressionAlgorithm.h"
#include "Feature.h"
#include "Features.h"
#include "HashAlgorithmUtil.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyFlag.h"
#include "KeySpec.h"
#include "KeySpecBuilder.h"
#include "KeySpecBuilderInterface.h"
#include "KeyType.h"
#include "PGPSignatureSubpacketGenerator.h"
#include "SymmetricKeyAlgorithm.h"
#include "java/lang/Deprecated.h"
#include "java/lang/annotation/Annotation.h"

@interface LibComAfterlogicPgpKeyGenerationKeySpecBuilder () {
 @public
  id<LibComAfterlogicPgpKeyGenerationTypeKeyType> type_;
  LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *hashedSubPackets_;
}

@end

J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyGenerationKeySpecBuilder, type_, id<LibComAfterlogicPgpKeyGenerationTypeKeyType>)
J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyGenerationKeySpecBuilder, hashedSubPackets_, LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *)

@interface LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl () {
 @public
  LibComAfterlogicPgpKeyGenerationKeySpecBuilder *this$0_;
}

@end

__attribute__((unused)) static IOSObjectArray *LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl__Annotations$0(void);

@interface LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl () {
 @public
  LibComAfterlogicPgpKeyGenerationKeySpecBuilder *this$0_;
}

@end

@interface LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl () {
 @public
  LibComAfterlogicPgpKeyGenerationKeySpecBuilder *this$0_;
}

@end

@interface LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl () {
 @public
  LibComAfterlogicPgpKeyGenerationKeySpecBuilder *this$0_;
}

@end

@interface LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl () {
 @public
  LibComAfterlogicPgpKeyGenerationKeySpecBuilder *this$0_;
}

@end

@implementation LibComAfterlogicPgpKeyGenerationKeySpecBuilder

- (instancetype)initWithLibComAfterlogicPgpKeyGenerationTypeKeyType:(id<LibComAfterlogicPgpKeyGenerationTypeKeyType>)type {
  LibComAfterlogicPgpKeyGenerationKeySpecBuilder_initWithLibComAfterlogicPgpKeyGenerationTypeKeyType_(self, type);
  return self;
}

- (id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithDetailedConfiguration>)withKeyFlagsWithLibComAfterlogicPgpAlgorithmKeyFlagArray:(IOSObjectArray *)flags {
  jint val = 0;
  {
    IOSObjectArray *a__ = flags;
    LibComAfterlogicPgpAlgorithmKeyFlag * const *b__ = ((IOSObjectArray *) nil_chk(a__))->buffer_;
    LibComAfterlogicPgpAlgorithmKeyFlag * const *e__ = b__ + a__->size_;
    while (b__ < e__) {
      LibComAfterlogicPgpAlgorithmKeyFlag *f = *b__++;
      val |= [((LibComAfterlogicPgpAlgorithmKeyFlag *) nil_chk(f)) getFlag];
    }
  }
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(self->hashedSubPackets_)) setKeyFlagsWithBoolean:false withInt:val];
  return new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(self);
}

- (id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithDetailedConfiguration>)withDefaultKeyFlags {
  return [self withKeyFlagsWithLibComAfterlogicPgpAlgorithmKeyFlagArray:[IOSObjectArray newArrayWithObjects:(id[]){ JreLoadEnum(LibComAfterlogicPgpAlgorithmKeyFlag, CERTIFY_OTHER), JreLoadEnum(LibComAfterlogicPgpAlgorithmKeyFlag, SIGN_DATA), JreLoadEnum(LibComAfterlogicPgpAlgorithmKeyFlag, ENCRYPT_COMMS), JreLoadEnum(LibComAfterlogicPgpAlgorithmKeyFlag, ENCRYPT_STORAGE), JreLoadEnum(LibComAfterlogicPgpAlgorithmKeyFlag, AUTHENTICATION) } count:5 type:LibComAfterlogicPgpAlgorithmKeyFlag_class_()]];
}

- (LibComAfterlogicPgpKeyGenerationKeySpec *)withInheritedSubPackets {
  return new_LibComAfterlogicPgpKeyGenerationKeySpec_initWithLibComAfterlogicPgpKeyGenerationTypeKeyType_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator_withBoolean_(type_, nil, true);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithDetailedConfiguration;", 0x81, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithDetailedConfiguration;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpec;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibComAfterlogicPgpKeyGenerationTypeKeyType:);
  methods[1].selector = @selector(withKeyFlagsWithLibComAfterlogicPgpAlgorithmKeyFlagArray:);
  methods[2].selector = @selector(withDefaultKeyFlags);
  methods[3].selector = @selector(withInheritedSubPackets);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "type_", "LLibComAfterlogicPgpKeyGenerationTypeKeyType;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashedSubPackets_", "LLibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibComAfterlogicPgpKeyGenerationTypeKeyType;", "withKeyFlags", "[LLibComAfterlogicPgpAlgorithmKeyFlag;", "LLibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl;LLibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl;LLibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl;LLibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl;LLibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyGenerationKeySpecBuilder = { "KeySpecBuilder", "lib.com.afterlogic.pgp.key.generation", ptrTable, methods, fields, 7, 0x1, 4, 2, -1, 3, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeyGenerationKeySpecBuilder;
}

@end

void LibComAfterlogicPgpKeyGenerationKeySpecBuilder_initWithLibComAfterlogicPgpKeyGenerationTypeKeyType_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *self, id<LibComAfterlogicPgpKeyGenerationTypeKeyType> type) {
  NSObject_init(self);
  self->hashedSubPackets_ = new_LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator_init();
  self->type_ = type;
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder *new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_initWithLibComAfterlogicPgpKeyGenerationTypeKeyType_(id<LibComAfterlogicPgpKeyGenerationTypeKeyType> type) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder, initWithLibComAfterlogicPgpKeyGenerationTypeKeyType_, type)
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder *create_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_initWithLibComAfterlogicPgpKeyGenerationTypeKeyType_(id<LibComAfterlogicPgpKeyGenerationTypeKeyType> type) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder, initWithLibComAfterlogicPgpKeyGenerationTypeKeyType_, type)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyGenerationKeySpecBuilder)

@implementation LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl

- (instancetype)initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder:(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *)outer$ {
  LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(self, outer$);
  return self;
}

- (id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithPreferredSymmetricAlgorithms>)withDetailedConfiguration {
  return new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(this$0_);
}

- (LibComAfterlogicPgpKeyGenerationKeySpec *)withDefaultAlgorithms {
  LibComAfterlogicPgpAlgorithmAlgorithmSuite *defaultSuite = LibComAfterlogicPgpAlgorithmAlgorithmSuite_getDefaultAlgorithmSuite();
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredCompressionAlgorithmsWithBoolean:false withIntArray:[((LibComAfterlogicPgpAlgorithmAlgorithmSuite *) nil_chk(defaultSuite)) getCompressionAlgorithmIds]];
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredSymmetricAlgorithmsWithBoolean:false withIntArray:[defaultSuite getSymmetricKeyAlgorithmIds]];
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredHashAlgorithmsWithBoolean:false withIntArray:[defaultSuite getHashAlgorithmIds]];
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setFeatureWithBoolean:false withByte:LibOrgBouncycastleBcpgSigFeatures_FEATURE_MODIFICATION_DETECTION];
  return new_LibComAfterlogicPgpKeyGenerationKeySpec_initWithLibComAfterlogicPgpKeyGenerationTypeKeyType_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator_withBoolean_(this$0_->type_, this$0_->hashedSubPackets_, false);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithPreferredSymmetricAlgorithms;", 0x1, -1, -1, -1, -1, 0, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpec;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder:);
  methods[1].selector = @selector(withDetailedConfiguration);
  methods[2].selector = @selector(withDefaultAlgorithms);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibComAfterlogicPgpKeyGenerationKeySpecBuilder;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { (void *)&LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl__Annotations$0, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilder;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl = { "WithDetailedConfigurationImpl", "lib.com.afterlogic.pgp.key.generation", ptrTable, methods, fields, 7, 0x0, 3, 1, 1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl;
}

@end

void LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl *self, LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  self->this$0_ = outer$;
  NSObject_init(self);
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl *new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl, initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_, outer$)
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl *create_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl, initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_, outer$)
}

IOSObjectArray *LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl__Annotations$0() {
  return [IOSObjectArray newArrayWithObjects:(id[]){ create_JavaLangDeprecated() } count:1 type:JavaLangAnnotationAnnotation_class_()];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithDetailedConfigurationImpl)

@implementation LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl

- (instancetype)initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder:(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *)outer$ {
  LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(self, outer$);
  return self;
}

- (id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithPreferredHashAlgorithms>)withPreferredSymmetricAlgorithmsWithLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithmArray:(IOSObjectArray *)algorithms {
  IOSIntArray *ids = [IOSIntArray newArrayWithLength:((IOSObjectArray *) nil_chk(algorithms))->size_];
  for (jint i = 0; i < ids->size_; i++) {
    *IOSIntArray_GetRef(ids, i) = [((LibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm *) nil_chk(IOSObjectArray_Get(algorithms, i))) getAlgorithmId];
  }
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredSymmetricAlgorithmsWithBoolean:false withIntArray:ids];
  return new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(this$0_);
}

- (id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithPreferredHashAlgorithms>)withDefaultSymmetricAlgorithms {
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredSymmetricAlgorithmsWithBoolean:false withIntArray:[((LibComAfterlogicPgpAlgorithmAlgorithmSuite *) nil_chk(LibComAfterlogicPgpAlgorithmAlgorithmSuite_getDefaultAlgorithmSuite())) getSymmetricKeyAlgorithmIds]];
  return new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(this$0_);
}

- (id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithFeatures>)withDefaultAlgorithms {
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredSymmetricAlgorithmsWithBoolean:false withIntArray:[((LibComAfterlogicPgpAlgorithmAlgorithmSuite *) nil_chk(LibComAfterlogicPgpAlgorithmAlgorithmSuite_getDefaultAlgorithmSuite())) getSymmetricKeyAlgorithmIds]];
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredCompressionAlgorithmsWithBoolean:false withIntArray:[((LibComAfterlogicPgpAlgorithmAlgorithmSuite *) nil_chk(LibComAfterlogicPgpAlgorithmAlgorithmSuite_getDefaultAlgorithmSuite())) getCompressionAlgorithmIds]];
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredHashAlgorithmsWithBoolean:false withIntArray:[((LibComAfterlogicPgpAlgorithmAlgorithmSuite *) nil_chk(LibComAfterlogicPgpAlgorithmAlgorithmSuite_getDefaultAlgorithmSuite())) getHashAlgorithmIds]];
  return new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(this$0_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithPreferredHashAlgorithms;", 0x81, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithPreferredHashAlgorithms;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithFeatures;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder:);
  methods[1].selector = @selector(withPreferredSymmetricAlgorithmsWithLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithmArray:);
  methods[2].selector = @selector(withDefaultSymmetricAlgorithms);
  methods[3].selector = @selector(withDefaultAlgorithms);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibComAfterlogicPgpKeyGenerationKeySpecBuilder;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "withPreferredSymmetricAlgorithms", "[LLibComAfterlogicPgpAlgorithmSymmetricKeyAlgorithm;", "LLibComAfterlogicPgpKeyGenerationKeySpecBuilder;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl = { "WithPreferredSymmetricAlgorithmsImpl", "lib.com.afterlogic.pgp.key.generation", ptrTable, methods, fields, 7, 0x0, 4, 1, 2, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl;
}

@end

void LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl *self, LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  self->this$0_ = outer$;
  NSObject_init(self);
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl *new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl, initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_, outer$)
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl *create_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl, initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_, outer$)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredSymmetricAlgorithmsImpl)

@implementation LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl

- (instancetype)initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder:(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *)outer$ {
  LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(self, outer$);
  return self;
}

- (id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithPreferredCompressionAlgorithms>)withPreferredHashAlgorithmsWithLibComAfterlogicPgpAlgorithmHashAlgorithmUtilArray:(IOSObjectArray *)algorithms {
  IOSIntArray *ids = [IOSIntArray newArrayWithLength:((IOSObjectArray *) nil_chk(algorithms))->size_];
  for (jint i = 0; i < ids->size_; i++) {
    *IOSIntArray_GetRef(ids, i) = [((LibComAfterlogicPgpAlgorithmHashAlgorithmUtil *) nil_chk(IOSObjectArray_Get(algorithms, i))) getAlgorithmId];
  }
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredHashAlgorithmsWithBoolean:false withIntArray:ids];
  return new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(this$0_);
}

- (id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithPreferredCompressionAlgorithms>)withDefaultHashAlgorithms {
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredHashAlgorithmsWithBoolean:false withIntArray:[((LibComAfterlogicPgpAlgorithmAlgorithmSuite *) nil_chk(LibComAfterlogicPgpAlgorithmAlgorithmSuite_getDefaultAlgorithmSuite())) getHashAlgorithmIds]];
  return new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(this$0_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithPreferredCompressionAlgorithms;", 0x81, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithPreferredCompressionAlgorithms;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder:);
  methods[1].selector = @selector(withPreferredHashAlgorithmsWithLibComAfterlogicPgpAlgorithmHashAlgorithmUtilArray:);
  methods[2].selector = @selector(withDefaultHashAlgorithms);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibComAfterlogicPgpKeyGenerationKeySpecBuilder;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "withPreferredHashAlgorithms", "[LLibComAfterlogicPgpAlgorithmHashAlgorithmUtil;", "LLibComAfterlogicPgpKeyGenerationKeySpecBuilder;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl = { "WithPreferredHashAlgorithmsImpl", "lib.com.afterlogic.pgp.key.generation", ptrTable, methods, fields, 7, 0x0, 3, 1, 2, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl;
}

@end

void LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl *self, LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  self->this$0_ = outer$;
  NSObject_init(self);
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl *new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl, initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_, outer$)
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl *create_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl, initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_, outer$)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredHashAlgorithmsImpl)

@implementation LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl

- (instancetype)initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder:(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *)outer$ {
  LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(self, outer$);
  return self;
}

- (id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithFeatures>)withPreferredCompressionAlgorithmsWithLibComAfterlogicPgpAlgorithmCompressionAlgorithmArray:(IOSObjectArray *)algorithms {
  IOSIntArray *ids = [IOSIntArray newArrayWithLength:((IOSObjectArray *) nil_chk(algorithms))->size_];
  for (jint i = 0; i < ids->size_; i++) {
    *IOSIntArray_GetRef(ids, i) = [((LibComAfterlogicPgpAlgorithmCompressionAlgorithm *) nil_chk(IOSObjectArray_Get(algorithms, i))) getAlgorithmId];
  }
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredCompressionAlgorithmsWithBoolean:false withIntArray:ids];
  return new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(this$0_);
}

- (id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithFeatures>)withDefaultCompressionAlgorithms {
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setPreferredCompressionAlgorithmsWithBoolean:false withIntArray:[((LibComAfterlogicPgpAlgorithmAlgorithmSuite *) nil_chk(LibComAfterlogicPgpAlgorithmAlgorithmSuite_getDefaultAlgorithmSuite())) getCompressionAlgorithmIds]];
  return new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(this$0_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithFeatures;", 0x81, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithFeatures;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder:);
  methods[1].selector = @selector(withPreferredCompressionAlgorithmsWithLibComAfterlogicPgpAlgorithmCompressionAlgorithmArray:);
  methods[2].selector = @selector(withDefaultCompressionAlgorithms);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibComAfterlogicPgpKeyGenerationKeySpecBuilder;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "withPreferredCompressionAlgorithms", "[LLibComAfterlogicPgpAlgorithmCompressionAlgorithm;", "LLibComAfterlogicPgpKeyGenerationKeySpecBuilder;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl = { "WithPreferredCompressionAlgorithmsImpl", "lib.com.afterlogic.pgp.key.generation", ptrTable, methods, fields, 7, 0x0, 3, 1, 2, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl;
}

@end

void LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl *self, LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  self->this$0_ = outer$;
  NSObject_init(self);
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl *new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl, initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_, outer$)
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl *create_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl, initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_, outer$)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithPreferredCompressionAlgorithmsImpl)

@implementation LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl

- (instancetype)initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder:(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *)outer$ {
  LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(self, outer$);
  return self;
}

- (id<LibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithFeatures>)withFeatureWithLibComAfterlogicPgpAlgorithmFeature:(LibComAfterlogicPgpAlgorithmFeature *)feature {
  [((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator *) nil_chk(this$0_->hashedSubPackets_)) setFeatureWithBoolean:false withByte:[((LibComAfterlogicPgpAlgorithmFeature *) nil_chk(feature)) getFeatureId]];
  return self;
}

- (LibComAfterlogicPgpKeyGenerationKeySpec *)done {
  return new_LibComAfterlogicPgpKeyGenerationKeySpec_initWithLibComAfterlogicPgpKeyGenerationTypeKeyType_withLibOrgBouncycastleOpenpgpPGPSignatureSubpacketGenerator_withBoolean_(this$0_->type_, this$0_->hashedSubPackets_, false);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpecBuilderInterface_WithFeatures;", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationKeySpec;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder:);
  methods[1].selector = @selector(withFeatureWithLibComAfterlogicPgpAlgorithmFeature:);
  methods[2].selector = @selector(done);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibComAfterlogicPgpKeyGenerationKeySpecBuilder;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "withFeature", "LLibComAfterlogicPgpAlgorithmFeature;", "LLibComAfterlogicPgpKeyGenerationKeySpecBuilder;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl = { "WithFeaturesImpl", "lib.com.afterlogic.pgp.key.generation", ptrTable, methods, fields, 7, 0x0, 3, 1, 2, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl;
}

@end

void LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl *self, LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  self->this$0_ = outer$;
  NSObject_init(self);
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl *new_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl, initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_, outer$)
}

LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl *create_LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl_initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_(LibComAfterlogicPgpKeyGenerationKeySpecBuilder *outer$) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl, initWithLibComAfterlogicPgpKeyGenerationKeySpecBuilder_, outer$)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyGenerationKeySpecBuilder_WithFeaturesImpl)
