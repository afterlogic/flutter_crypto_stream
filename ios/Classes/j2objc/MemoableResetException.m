//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/MemoableResetException.java
//

#include "J2ObjC_source.h"
#include "MemoableResetException.h"
#include "java/lang/ClassCastException.h"

@implementation LibOrgBouncycastleUtilMemoableResetException

- (instancetype)initWithNSString:(NSString *)msg {
  LibOrgBouncycastleUtilMemoableResetException_initWithNSString_(self, msg);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilMemoableResetException = { "MemoableResetException", "lib.org.bouncycastle.util", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilMemoableResetException;
}

@end

void LibOrgBouncycastleUtilMemoableResetException_initWithNSString_(LibOrgBouncycastleUtilMemoableResetException *self, NSString *msg) {
  JavaLangClassCastException_initWithNSString_(self, msg);
}

LibOrgBouncycastleUtilMemoableResetException *new_LibOrgBouncycastleUtilMemoableResetException_initWithNSString_(NSString *msg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilMemoableResetException, initWithNSString_, msg)
}

LibOrgBouncycastleUtilMemoableResetException *create_LibOrgBouncycastleUtilMemoableResetException_initWithNSString_(NSString *msg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilMemoableResetException, initWithNSString_, msg)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilMemoableResetException)
