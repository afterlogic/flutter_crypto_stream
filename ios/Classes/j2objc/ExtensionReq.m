//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/ExtensionReq.java
//

#include "ASN1Encodable.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "Asn1CmcUtils.h"
#include "DERSequence.h"
#include "Extension.h"
#include "ExtensionReq.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleAsn1CmcExtensionReq () {
 @public
  IOSObjectArray *extensions_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcExtensionReq, extensions_, IOSObjectArray *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcExtensionReq *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcExtensionReq *new_LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcExtensionReq *create_LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmcExtensionReq

+ (LibOrgBouncycastleAsn1CmcExtensionReq *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmcExtensionReq_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1CmcExtensionReq *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                     withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CmcExtensionReq_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509Extension:(LibOrgBouncycastleAsn1X509Extension *)Extension {
  LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1X509Extension_(self, Extension);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509ExtensionArray:(IOSObjectArray *)extensions {
  LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1X509ExtensionArray_(self, extensions);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (IOSObjectArray *)getExtensions {
  return LibOrgBouncycastleAsn1CmcAsn1CmcUtils_cloneWithLibOrgBouncycastleAsn1X509ExtensionArray_(extensions_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(extensions_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1CmcExtensionReq;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcExtensionReq;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 5, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1X509Extension;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1X509Extension:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1X509ExtensionArray:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[5].selector = @selector(getExtensions);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "extensions_", "[LLibOrgBouncycastleAsn1X509Extension;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LLibOrgBouncycastleAsn1X509Extension;", "[LLibOrgBouncycastleAsn1X509Extension;", "LLibOrgBouncycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmcExtensionReq = { "ExtensionReq", "lib.org.bouncycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 7, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmcExtensionReq;
}

@end

LibOrgBouncycastleAsn1CmcExtensionReq *LibOrgBouncycastleAsn1CmcExtensionReq_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmcExtensionReq_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmcExtensionReq class]]) {
    return (LibOrgBouncycastleAsn1CmcExtensionReq *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

LibOrgBouncycastleAsn1CmcExtensionReq *LibOrgBouncycastleAsn1CmcExtensionReq_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CmcExtensionReq_initialize();
  return LibOrgBouncycastleAsn1CmcExtensionReq_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

void LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1X509Extension_(LibOrgBouncycastleAsn1CmcExtensionReq *self, LibOrgBouncycastleAsn1X509Extension *Extension) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->extensions_ = [IOSObjectArray newArrayWithObjects:(id[]){ Extension } count:1 type:LibOrgBouncycastleAsn1X509Extension_class_()];
}

LibOrgBouncycastleAsn1CmcExtensionReq *new_LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1X509Extension_(LibOrgBouncycastleAsn1X509Extension *Extension) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcExtensionReq, initWithLibOrgBouncycastleAsn1X509Extension_, Extension)
}

LibOrgBouncycastleAsn1CmcExtensionReq *create_LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1X509Extension_(LibOrgBouncycastleAsn1X509Extension *Extension) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcExtensionReq, initWithLibOrgBouncycastleAsn1X509Extension_, Extension)
}

void LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1X509ExtensionArray_(LibOrgBouncycastleAsn1CmcExtensionReq *self, IOSObjectArray *extensions) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->extensions_ = LibOrgBouncycastleAsn1CmcAsn1CmcUtils_cloneWithLibOrgBouncycastleAsn1X509ExtensionArray_(extensions);
}

LibOrgBouncycastleAsn1CmcExtensionReq *new_LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1X509ExtensionArray_(IOSObjectArray *extensions) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcExtensionReq, initWithLibOrgBouncycastleAsn1X509ExtensionArray_, extensions)
}

LibOrgBouncycastleAsn1CmcExtensionReq *create_LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1X509ExtensionArray_(IOSObjectArray *extensions) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcExtensionReq, initWithLibOrgBouncycastleAsn1X509ExtensionArray_, extensions)
}

void LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcExtensionReq *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->extensions_ = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] type:LibOrgBouncycastleAsn1X509Extension_class_()];
  for (jint i = 0; i != [seq size]; i++) {
    (void) IOSObjectArray_Set(self->extensions_, i, LibOrgBouncycastleAsn1X509Extension_getInstanceWithId_([seq getObjectAtWithInt:i]));
  }
}

LibOrgBouncycastleAsn1CmcExtensionReq *new_LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcExtensionReq, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcExtensionReq *create_LibOrgBouncycastleAsn1CmcExtensionReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcExtensionReq, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmcExtensionReq)
