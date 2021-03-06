//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/StoreException.java
//

#include "J2ObjC_source.h"
#include "StoreException.h"
#include "java/lang/RuntimeException.h"
#include "java/lang/Throwable.h"

@interface LibOrgBouncycastleUtilStoreException () {
 @public
  JavaLangThrowable *_e_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleUtilStoreException, _e_, JavaLangThrowable *)

@implementation LibOrgBouncycastleUtilStoreException

- (instancetype)initWithNSString:(NSString *)msg
           withJavaLangThrowable:(JavaLangThrowable *)cause {
  LibOrgBouncycastleUtilStoreException_initWithNSString_withJavaLangThrowable_(self, msg, cause);
  return self;
}

- (JavaLangThrowable *)getCause {
  return _e_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaLangThrowable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withJavaLangThrowable:);
  methods[1].selector = @selector(getCause);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_e_", "LJavaLangThrowable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LJavaLangThrowable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilStoreException = { "StoreException", "lib.org.bouncycastle.util", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilStoreException;
}

@end

void LibOrgBouncycastleUtilStoreException_initWithNSString_withJavaLangThrowable_(LibOrgBouncycastleUtilStoreException *self, NSString *msg, JavaLangThrowable *cause) {
  JavaLangRuntimeException_initWithNSString_(self, msg);
  self->_e_ = cause;
}

LibOrgBouncycastleUtilStoreException *new_LibOrgBouncycastleUtilStoreException_initWithNSString_withJavaLangThrowable_(NSString *msg, JavaLangThrowable *cause) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilStoreException, initWithNSString_withJavaLangThrowable_, msg, cause)
}

LibOrgBouncycastleUtilStoreException *create_LibOrgBouncycastleUtilStoreException_initWithNSString_withJavaLangThrowable_(NSString *msg, JavaLangThrowable *cause) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilStoreException, initWithNSString_withJavaLangThrowable_, msg, cause)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilStoreException)
