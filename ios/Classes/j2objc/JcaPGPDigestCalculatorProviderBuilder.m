//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/JcaPGPDigestCalculatorProviderBuilder.java
//

#include "DefaultJcaJceHelper.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaPGPDigestCalculatorProviderBuilder.h"
#include "NamedJcaJceHelper.h"
#include "OperatorHelper.h"
#include "PGPDigestCalculator.h"
#include "PGPDigestCalculatorProvider.h"
#include "PGPException.h"
#include "ProviderJcaJceHelper.h"
#include "java/io/OutputStream.h"
#include "java/security/GeneralSecurityException.h"
#include "java/security/MessageDigest.h"
#include "java/security/Provider.h"

@class LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream;

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder () {
 @public
  LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper *helper_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder, helper_, LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper *)

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1 : NSObject < LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider > {
 @public
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *this$0_;
}

- (instancetype)initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder:(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *)outer$;

- (id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)getWithInt:(jint)algorithm;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1 *self, LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1 *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1 *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$);

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1 : NSObject < LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator > {
 @public
  jint val$algorithm_;
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *val$stream_;
  JavaSecurityMessageDigest *val$dig_;
}

- (instancetype)initWithInt:(jint)capture$0
withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream:(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *)capture$1
withJavaSecurityMessageDigest:(JavaSecurityMessageDigest *)capture$2;

- (jint)getAlgorithm;

- (JavaIoOutputStream *)getOutputStream;

- (IOSByteArray *)getDigest;

- (void)reset;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_withJavaSecurityMessageDigest_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1 *self, jint capture$0, LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *capture$1, JavaSecurityMessageDigest *capture$2);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1 *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_withJavaSecurityMessageDigest_(jint capture$0, LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *capture$1, JavaSecurityMessageDigest *capture$2) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1 *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_withJavaSecurityMessageDigest_(jint capture$0, LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *capture$1, JavaSecurityMessageDigest *capture$2);

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream : JavaIoOutputStream {
 @public
  JavaSecurityMessageDigest *dig_;
}

- (instancetype)initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder:(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *)outer$
                                                                       withJavaSecurityMessageDigest:(JavaSecurityMessageDigest *)dig;

- (void)writeWithByteArray:(IOSByteArray *)bytes
                   withInt:(jint)off
                   withInt:(jint)len;

- (void)writeWithByteArray:(IOSByteArray *)bytes;

- (void)writeWithInt:(jint)b;

- (IOSByteArray *)getDigest;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream, dig_, JavaSecurityMessageDigest *)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_withJavaSecurityMessageDigest_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *self, LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$, JavaSecurityMessageDigest *dig);

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_withJavaSecurityMessageDigest_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$, JavaSecurityMessageDigest *dig) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_withJavaSecurityMessageDigest_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$, JavaSecurityMessageDigest *dig);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream)

@implementation LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *)setProviderWithJavaSecurityProvider:(JavaSecurityProvider *)provider {
  self->helper_ = new_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(new_LibOrgBouncycastleJcajceUtilProviderJcaJceHelper_initWithJavaSecurityProvider_(provider));
  return self;
}

- (LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *)setProviderWithNSString:(NSString *)providerName {
  self->helper_ = new_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(new_LibOrgBouncycastleJcajceUtilNamedJcaJceHelper_initWithNSString_(providerName));
  return self;
}

- (id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider>)build {
  return new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder;", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder;", 0x1, 0, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculatorProvider;", 0x1, -1, -1, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(setProviderWithJavaSecurityProvider:);
  methods[2].selector = @selector(setProviderWithNSString:);
  methods[3].selector = @selector(build);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "helper_", "LLibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "setProvider", "LJavaSecurityProvider;", "LNSString;", "LLibOrgBouncycastleOpenpgpPGPException;", "LLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder = { "JcaPGPDigestCalculatorProviderBuilder", "lib.org.bouncycastle.openpgp.operator.jcajce", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, 4, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder;
}

@end

void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_init(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *self) {
  NSObject_init(self);
  self->helper_ = new_LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(new_LibOrgBouncycastleJcajceUtilDefaultJcaJceHelper_init());
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder, init)
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder)

@implementation LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1

- (instancetype)initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder:(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *)outer$ {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_(self, outer$);
  return self;
}

- (id<LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator>)getWithInt:(jint)algorithm {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *stream;
  JavaSecurityMessageDigest *dig;
  @try {
    dig = [((LibOrgBouncycastleOpenpgpOperatorJcajceOperatorHelper *) nil_chk(this$0_->helper_)) createDigestWithInt:algorithm];
    stream = new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_withJavaSecurityMessageDigest_(this$0_, dig);
  }
  @catch (JavaSecurityGeneralSecurityException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(JreStrcat("$@", @"exception on setup: ", e), e);
  }
  return new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_withJavaSecurityMessageDigest_(algorithm, stream, dig);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator;", 0x1, 0, 1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder:);
  methods[1].selector = @selector(getWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "get", "I", "LLibOrgBouncycastleOpenpgpPGPException;", "LLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder;", "build" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1 = { "", "lib.org.bouncycastle.openpgp.operator.jcajce", ptrTable, methods, fields, 7, 0x8010, 2, 1, 3, -1, 4, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1;
}

@end

void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1 *self, LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$) {
  self->this$0_ = outer$;
  NSObject_init(self);
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1 *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1, initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_, outer$)
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1 *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1, initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_, outer$)
}

@implementation LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1

- (instancetype)initWithInt:(jint)capture$0
withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream:(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *)capture$1
withJavaSecurityMessageDigest:(JavaSecurityMessageDigest *)capture$2 {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_withJavaSecurityMessageDigest_(self, capture$0, capture$1, capture$2);
  return self;
}

- (jint)getAlgorithm {
  return val$algorithm_;
}

- (JavaIoOutputStream *)getOutputStream {
  return val$stream_;
}

- (IOSByteArray *)getDigest {
  return [((LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *) nil_chk(val$stream_)) getDigest];
}

- (void)reset {
  [((JavaSecurityMessageDigest *) nil_chk(val$dig_)) reset];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaIoOutputStream;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream:withJavaSecurityMessageDigest:);
  methods[1].selector = @selector(getAlgorithm);
  methods[2].selector = @selector(getOutputStream);
  methods[3].selector = @selector(getDigest);
  methods[4].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "val$algorithm_", "I", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$stream_", "LLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$dig_", "LJavaSecurityMessageDigest;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1;", "getWithInt:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1 = { "", "lib.org.bouncycastle.openpgp.operator.jcajce", ptrTable, methods, fields, 7, 0x8010, 5, 3, 0, -1, 1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1;
}

@end

void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_withJavaSecurityMessageDigest_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1 *self, jint capture$0, LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *capture$1, JavaSecurityMessageDigest *capture$2) {
  self->val$algorithm_ = capture$0;
  self->val$stream_ = capture$1;
  self->val$dig_ = capture$2;
  NSObject_init(self);
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1 *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_withJavaSecurityMessageDigest_(jint capture$0, LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *capture$1, JavaSecurityMessageDigest *capture$2) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1, initWithInt_withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_withJavaSecurityMessageDigest_, capture$0, capture$1, capture$2)
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1 *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1_initWithInt_withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_withJavaSecurityMessageDigest_(jint capture$0, LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *capture$1, JavaSecurityMessageDigest *capture$2) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_1_1, initWithInt_withLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_withJavaSecurityMessageDigest_, capture$0, capture$1, capture$2)
}

@implementation LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream

- (instancetype)initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder:(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *)outer$
                                                                       withJavaSecurityMessageDigest:(JavaSecurityMessageDigest *)dig {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_withJavaSecurityMessageDigest_(self, outer$, dig);
  return self;
}

- (void)writeWithByteArray:(IOSByteArray *)bytes
                   withInt:(jint)off
                   withInt:(jint)len {
  [((JavaSecurityMessageDigest *) nil_chk(dig_)) updateWithByteArray:bytes withInt:off withInt:len];
}

- (void)writeWithByteArray:(IOSByteArray *)bytes {
  [((JavaSecurityMessageDigest *) nil_chk(dig_)) updateWithByteArray:bytes];
}

- (void)writeWithInt:(jint)b {
  [((JavaSecurityMessageDigest *) nil_chk(dig_)) updateWithByte:(jbyte) b];
}

- (IOSByteArray *)getDigest {
  return [((JavaSecurityMessageDigest *) nil_chk(dig_)) digest];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 4, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 5, 3, -1, -1, -1 },
    { NULL, "[B", 0x0, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder:withJavaSecurityMessageDigest:);
  methods[1].selector = @selector(writeWithByteArray:withInt:withInt:);
  methods[2].selector = @selector(writeWithByteArray:);
  methods[3].selector = @selector(writeWithInt:);
  methods[4].selector = @selector(getDigest);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "dig_", "LJavaSecurityMessageDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecurityMessageDigest;", "write", "[BII", "LJavaIoIOException;", "[B", "I", "LLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream = { "DigestOutputStream", "lib.org.bouncycastle.openpgp.operator.jcajce", ptrTable, methods, fields, 7, 0x2, 5, 1, 6, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream;
}

@end

void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_withJavaSecurityMessageDigest_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *self, LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$, JavaSecurityMessageDigest *dig) {
  JavaIoOutputStream_init(self);
  self->dig_ = dig;
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_withJavaSecurityMessageDigest_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$, JavaSecurityMessageDigest *dig) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream, initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_withJavaSecurityMessageDigest_, outer$, dig)
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream_initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_withJavaSecurityMessageDigest_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder *outer$, JavaSecurityMessageDigest *dig) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream, initWithLibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_withJavaSecurityMessageDigest_, outer$, dig)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder_DigestOutputStream)