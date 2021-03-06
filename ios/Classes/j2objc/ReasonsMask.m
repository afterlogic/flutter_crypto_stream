//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/ReasonsMask.java
//

#include "J2ObjC_source.h"
#include "ReasonFlags.h"
#include "ReasonsMask.h"

@interface LibOrgBouncycastleJceProviderReasonsMask () {
 @public
  jint _reasons_;
}

- (instancetype)initWithInt:(jint)reasons;

@end

__attribute__((unused)) static void LibOrgBouncycastleJceProviderReasonsMask_initWithInt_(LibOrgBouncycastleJceProviderReasonsMask *self, jint reasons);

__attribute__((unused)) static LibOrgBouncycastleJceProviderReasonsMask *new_LibOrgBouncycastleJceProviderReasonsMask_initWithInt_(jint reasons) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJceProviderReasonsMask *create_LibOrgBouncycastleJceProviderReasonsMask_initWithInt_(jint reasons);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleJceProviderReasonsMask)

LibOrgBouncycastleJceProviderReasonsMask *LibOrgBouncycastleJceProviderReasonsMask_allReasons;

@implementation LibOrgBouncycastleJceProviderReasonsMask

+ (LibOrgBouncycastleJceProviderReasonsMask *)allReasons {
  return LibOrgBouncycastleJceProviderReasonsMask_allReasons;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509ReasonFlags:(LibOrgBouncycastleAsn1X509ReasonFlags *)reasons {
  LibOrgBouncycastleJceProviderReasonsMask_initWithLibOrgBouncycastleAsn1X509ReasonFlags_(self, reasons);
  return self;
}

- (instancetype)initWithInt:(jint)reasons {
  LibOrgBouncycastleJceProviderReasonsMask_initWithInt_(self, reasons);
  return self;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJceProviderReasonsMask_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)addReasonsWithLibOrgBouncycastleJceProviderReasonsMask:(LibOrgBouncycastleJceProviderReasonsMask *)mask {
  _reasons_ = _reasons_ | [((LibOrgBouncycastleJceProviderReasonsMask *) nil_chk(mask)) getReasons];
}

- (jboolean)isAllReasons {
  return _reasons_ == ((LibOrgBouncycastleJceProviderReasonsMask *) nil_chk(LibOrgBouncycastleJceProviderReasonsMask_allReasons))->_reasons_ ? true : false;
}

- (LibOrgBouncycastleJceProviderReasonsMask *)intersectWithLibOrgBouncycastleJceProviderReasonsMask:(LibOrgBouncycastleJceProviderReasonsMask *)mask {
  LibOrgBouncycastleJceProviderReasonsMask *_mask = new_LibOrgBouncycastleJceProviderReasonsMask_init();
  [_mask addReasonsWithLibOrgBouncycastleJceProviderReasonsMask:new_LibOrgBouncycastleJceProviderReasonsMask_initWithInt_(_reasons_ & [((LibOrgBouncycastleJceProviderReasonsMask *) nil_chk(mask)) getReasons])];
  return _mask;
}

- (jboolean)hasNewReasonsWithLibOrgBouncycastleJceProviderReasonsMask:(LibOrgBouncycastleJceProviderReasonsMask *)mask {
  return ((_reasons_ | ([((LibOrgBouncycastleJceProviderReasonsMask *) nil_chk(mask)) getReasons] ^ _reasons_)) != 0);
}

- (jint)getReasons {
  return _reasons_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 2, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJceProviderReasonsMask;", 0x0, 4, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, 5, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1X509ReasonFlags:);
  methods[1].selector = @selector(initWithInt:);
  methods[2].selector = @selector(init);
  methods[3].selector = @selector(addReasonsWithLibOrgBouncycastleJceProviderReasonsMask:);
  methods[4].selector = @selector(isAllReasons);
  methods[5].selector = @selector(intersectWithLibOrgBouncycastleJceProviderReasonsMask:);
  methods[6].selector = @selector(hasNewReasonsWithLibOrgBouncycastleJceProviderReasonsMask:);
  methods[7].selector = @selector(getReasons);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_reasons_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "allReasons", "LLibOrgBouncycastleJceProviderReasonsMask;", .constantValue.asLong = 0, 0x18, -1, 6, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1X509ReasonFlags;", "I", "addReasons", "LLibOrgBouncycastleJceProviderReasonsMask;", "intersect", "hasNewReasons", &LibOrgBouncycastleJceProviderReasonsMask_allReasons };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceProviderReasonsMask = { "ReasonsMask", "lib.org.bouncycastle.jce.provider", ptrTable, methods, fields, 7, 0x0, 8, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceProviderReasonsMask;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleJceProviderReasonsMask class]) {
    LibOrgBouncycastleJceProviderReasonsMask_allReasons = new_LibOrgBouncycastleJceProviderReasonsMask_initWithInt_(LibOrgBouncycastleAsn1X509ReasonFlags_aACompromise | LibOrgBouncycastleAsn1X509ReasonFlags_affiliationChanged | LibOrgBouncycastleAsn1X509ReasonFlags_cACompromise | LibOrgBouncycastleAsn1X509ReasonFlags_certificateHold | LibOrgBouncycastleAsn1X509ReasonFlags_cessationOfOperation | LibOrgBouncycastleAsn1X509ReasonFlags_keyCompromise | LibOrgBouncycastleAsn1X509ReasonFlags_privilegeWithdrawn | LibOrgBouncycastleAsn1X509ReasonFlags_unused | LibOrgBouncycastleAsn1X509ReasonFlags_superseded);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleJceProviderReasonsMask)
  }
}

@end

void LibOrgBouncycastleJceProviderReasonsMask_initWithLibOrgBouncycastleAsn1X509ReasonFlags_(LibOrgBouncycastleJceProviderReasonsMask *self, LibOrgBouncycastleAsn1X509ReasonFlags *reasons) {
  NSObject_init(self);
  self->_reasons_ = [((LibOrgBouncycastleAsn1X509ReasonFlags *) nil_chk(reasons)) intValue];
}

LibOrgBouncycastleJceProviderReasonsMask *new_LibOrgBouncycastleJceProviderReasonsMask_initWithLibOrgBouncycastleAsn1X509ReasonFlags_(LibOrgBouncycastleAsn1X509ReasonFlags *reasons) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderReasonsMask, initWithLibOrgBouncycastleAsn1X509ReasonFlags_, reasons)
}

LibOrgBouncycastleJceProviderReasonsMask *create_LibOrgBouncycastleJceProviderReasonsMask_initWithLibOrgBouncycastleAsn1X509ReasonFlags_(LibOrgBouncycastleAsn1X509ReasonFlags *reasons) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderReasonsMask, initWithLibOrgBouncycastleAsn1X509ReasonFlags_, reasons)
}

void LibOrgBouncycastleJceProviderReasonsMask_initWithInt_(LibOrgBouncycastleJceProviderReasonsMask *self, jint reasons) {
  NSObject_init(self);
  self->_reasons_ = reasons;
}

LibOrgBouncycastleJceProviderReasonsMask *new_LibOrgBouncycastleJceProviderReasonsMask_initWithInt_(jint reasons) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderReasonsMask, initWithInt_, reasons)
}

LibOrgBouncycastleJceProviderReasonsMask *create_LibOrgBouncycastleJceProviderReasonsMask_initWithInt_(jint reasons) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderReasonsMask, initWithInt_, reasons)
}

void LibOrgBouncycastleJceProviderReasonsMask_init(LibOrgBouncycastleJceProviderReasonsMask *self) {
  LibOrgBouncycastleJceProviderReasonsMask_initWithInt_(self, 0);
}

LibOrgBouncycastleJceProviderReasonsMask *new_LibOrgBouncycastleJceProviderReasonsMask_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceProviderReasonsMask, init)
}

LibOrgBouncycastleJceProviderReasonsMask *create_LibOrgBouncycastleJceProviderReasonsMask_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceProviderReasonsMask, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceProviderReasonsMask)
