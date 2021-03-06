//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/CryptoException.java
//

#include "CryptoException.h"
#include "J2ObjC_source.h"
#include "java/lang/Exception.h"
#include "java/lang/Throwable.h"

@interface LibOrgBouncycastleCryptoCryptoException () {
 @public
  JavaLangThrowable *cause_CryptoException_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoCryptoException, cause_CryptoException_, JavaLangThrowable *)

@implementation LibOrgBouncycastleCryptoCryptoException

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoCryptoException_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithNSString:(NSString *)message {
  LibOrgBouncycastleCryptoCryptoException_initWithNSString_(self, message);
  return self;
}

- (instancetype)initWithNSString:(NSString *)message
           withJavaLangThrowable:(JavaLangThrowable *)cause {
  LibOrgBouncycastleCryptoCryptoException_initWithNSString_withJavaLangThrowable_(self, message, cause);
  return self;
}

- (JavaLangThrowable *)getCause {
  return cause_CryptoException_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LJavaLangThrowable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithNSString:);
  methods[2].selector = @selector(initWithNSString:withJavaLangThrowable:);
  methods[3].selector = @selector(getCause);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cause_CryptoException_", "LJavaLangThrowable;", .constantValue.asLong = 0, 0x2, 2, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "LNSString;LJavaLangThrowable;", "cause" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoCryptoException = { "CryptoException", "lib.org.bouncycastle.crypto", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoCryptoException;
}

@end

void LibOrgBouncycastleCryptoCryptoException_init(LibOrgBouncycastleCryptoCryptoException *self) {
  JavaLangException_init(self);
}

LibOrgBouncycastleCryptoCryptoException *new_LibOrgBouncycastleCryptoCryptoException_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoCryptoException, init)
}

LibOrgBouncycastleCryptoCryptoException *create_LibOrgBouncycastleCryptoCryptoException_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoCryptoException, init)
}

void LibOrgBouncycastleCryptoCryptoException_initWithNSString_(LibOrgBouncycastleCryptoCryptoException *self, NSString *message) {
  JavaLangException_initWithNSString_(self, message);
}

LibOrgBouncycastleCryptoCryptoException *new_LibOrgBouncycastleCryptoCryptoException_initWithNSString_(NSString *message) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoCryptoException, initWithNSString_, message)
}

LibOrgBouncycastleCryptoCryptoException *create_LibOrgBouncycastleCryptoCryptoException_initWithNSString_(NSString *message) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoCryptoException, initWithNSString_, message)
}

void LibOrgBouncycastleCryptoCryptoException_initWithNSString_withJavaLangThrowable_(LibOrgBouncycastleCryptoCryptoException *self, NSString *message, JavaLangThrowable *cause) {
  JavaLangException_initWithNSString_(self, message);
  self->cause_CryptoException_ = cause;
}

LibOrgBouncycastleCryptoCryptoException *new_LibOrgBouncycastleCryptoCryptoException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoCryptoException, initWithNSString_withJavaLangThrowable_, message, cause)
}

LibOrgBouncycastleCryptoCryptoException *create_LibOrgBouncycastleCryptoCryptoException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoCryptoException, initWithNSString_withJavaLangThrowable_, message, cause)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoCryptoException)
