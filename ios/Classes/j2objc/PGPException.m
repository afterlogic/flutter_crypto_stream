//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPException.java
//

#include "J2ObjC_source.h"
#include "PGPException.h"
#include "java/lang/Exception.h"
#include "java/lang/Throwable.h"

@implementation LibOrgBouncycastleOpenpgpPGPException

- (instancetype)initWithNSString:(NSString *)message {
  LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(self, message);
  return self;
}

- (instancetype)initWithNSString:(NSString *)message
           withJavaLangException:(JavaLangException *)underlying {
  LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(self, message, underlying);
  return self;
}

- (JavaLangException *)getUnderlyingException {
  return underlying_;
}

- (JavaLangThrowable *)getCause {
  return underlying_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LJavaLangException;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaLangThrowable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(initWithNSString:withJavaLangException:);
  methods[2].selector = @selector(getUnderlyingException);
  methods[3].selector = @selector(getCause);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "underlying_", "LJavaLangException;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "LNSString;LJavaLangException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpPGPException = { "PGPException", "lib.org.bouncycastle.openpgp", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpPGPException;
}

@end

void LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(LibOrgBouncycastleOpenpgpPGPException *self, NSString *message) {
  JavaLangException_initWithNSString_(self, message);
}

LibOrgBouncycastleOpenpgpPGPException *new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(NSString *message) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPException, initWithNSString_, message)
}

LibOrgBouncycastleOpenpgpPGPException *create_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(NSString *message) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPException, initWithNSString_, message)
}

void LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(LibOrgBouncycastleOpenpgpPGPException *self, NSString *message, JavaLangException *underlying) {
  JavaLangException_initWithNSString_(self, message);
  self->underlying_ = underlying;
}

LibOrgBouncycastleOpenpgpPGPException *new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(NSString *message, JavaLangException *underlying) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPException, initWithNSString_withJavaLangException_, message, underlying)
}

LibOrgBouncycastleOpenpgpPGPException *create_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_withJavaLangException_(NSString *message, JavaLangException *underlying) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPException, initWithNSString_withJavaLangException_, message, underlying)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpPGPException)
