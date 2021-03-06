//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/exception/ExtCertPathBuilderException.java
//

#include "ExtCertPathBuilderException.h"
#include "J2ObjC_source.h"
#include "java/lang/Throwable.h"
#include "java/security/cert/CertPath.h"
#include "java/security/cert/CertPathBuilderException.h"

@interface LibOrgBouncycastleJceExceptionExtCertPathBuilderException () {
 @public
  JavaLangThrowable *cause_ExtCertPathBuilderException_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceExceptionExtCertPathBuilderException, cause_ExtCertPathBuilderException_, JavaLangThrowable *)

@implementation LibOrgBouncycastleJceExceptionExtCertPathBuilderException

- (instancetype)initWithNSString:(NSString *)message
           withJavaLangThrowable:(JavaLangThrowable *)cause {
  LibOrgBouncycastleJceExceptionExtCertPathBuilderException_initWithNSString_withJavaLangThrowable_(self, message, cause);
  return self;
}

- (instancetype)initWithNSString:(NSString *)msg
           withJavaLangThrowable:(JavaLangThrowable *)cause
    withJavaSecurityCertCertPath:(JavaSecurityCertCertPath *)certPath
                         withInt:(jint)index {
  LibOrgBouncycastleJceExceptionExtCertPathBuilderException_initWithNSString_withJavaLangThrowable_withJavaSecurityCertCertPath_withInt_(self, msg, cause, certPath, index);
  return self;
}

- (JavaLangThrowable *)getCause {
  return cause_ExtCertPathBuilderException_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LJavaLangThrowable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withJavaLangThrowable:);
  methods[1].selector = @selector(initWithNSString:withJavaLangThrowable:withJavaSecurityCertCertPath:withInt:);
  methods[2].selector = @selector(getCause);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cause_ExtCertPathBuilderException_", "LJavaLangThrowable;", .constantValue.asLong = 0, 0x2, 2, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LJavaLangThrowable;", "LNSString;LJavaLangThrowable;LJavaSecurityCertCertPath;I", "cause" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceExceptionExtCertPathBuilderException = { "ExtCertPathBuilderException", "lib.org.bouncycastle.jce.exception", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceExceptionExtCertPathBuilderException;
}

@end

void LibOrgBouncycastleJceExceptionExtCertPathBuilderException_initWithNSString_withJavaLangThrowable_(LibOrgBouncycastleJceExceptionExtCertPathBuilderException *self, NSString *message, JavaLangThrowable *cause) {
  JavaSecurityCertCertPathBuilderException_initWithNSString_(self, message);
  self->cause_ExtCertPathBuilderException_ = cause;
}

LibOrgBouncycastleJceExceptionExtCertPathBuilderException *new_LibOrgBouncycastleJceExceptionExtCertPathBuilderException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceExceptionExtCertPathBuilderException, initWithNSString_withJavaLangThrowable_, message, cause)
}

LibOrgBouncycastleJceExceptionExtCertPathBuilderException *create_LibOrgBouncycastleJceExceptionExtCertPathBuilderException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceExceptionExtCertPathBuilderException, initWithNSString_withJavaLangThrowable_, message, cause)
}

void LibOrgBouncycastleJceExceptionExtCertPathBuilderException_initWithNSString_withJavaLangThrowable_withJavaSecurityCertCertPath_withInt_(LibOrgBouncycastleJceExceptionExtCertPathBuilderException *self, NSString *msg, JavaLangThrowable *cause, JavaSecurityCertCertPath *certPath, jint index) {
  JavaSecurityCertCertPathBuilderException_initWithNSString_withJavaLangThrowable_(self, msg, cause);
  self->cause_ExtCertPathBuilderException_ = cause;
}

LibOrgBouncycastleJceExceptionExtCertPathBuilderException *new_LibOrgBouncycastleJceExceptionExtCertPathBuilderException_initWithNSString_withJavaLangThrowable_withJavaSecurityCertCertPath_withInt_(NSString *msg, JavaLangThrowable *cause, JavaSecurityCertCertPath *certPath, jint index) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceExceptionExtCertPathBuilderException, initWithNSString_withJavaLangThrowable_withJavaSecurityCertCertPath_withInt_, msg, cause, certPath, index)
}

LibOrgBouncycastleJceExceptionExtCertPathBuilderException *create_LibOrgBouncycastleJceExceptionExtCertPathBuilderException_initWithNSString_withJavaLangThrowable_withJavaSecurityCertCertPath_withInt_(NSString *msg, JavaLangThrowable *cause, JavaSecurityCertCertPath *certPath, jint index) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceExceptionExtCertPathBuilderException, initWithNSString_withJavaLangThrowable_withJavaSecurityCertCertPath_withInt_, msg, cause, certPath, index)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceExceptionExtCertPathBuilderException)
