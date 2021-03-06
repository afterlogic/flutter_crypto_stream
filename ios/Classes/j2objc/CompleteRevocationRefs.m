//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/CompleteRevocationRefs.java
//

#include "ASN1Encodable.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "CompleteRevocationRefs.h"
#include "CrlOcspRef.h"
#include "DERSequence.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1EsfCompleteRevocationRefs () {
 @public
  LibOrgBouncycastleAsn1ASN1Sequence *crlOcspRefs_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfCompleteRevocationRefs, crlOcspRefs_, LibOrgBouncycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *new_LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *create_LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1EsfCompleteRevocationRefs

+ (LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1EsfCrlOcspRefArray:(IOSObjectArray *)crlOcspRefs {
  LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1EsfCrlOcspRefArray_(self, crlOcspRefs);
  return self;
}

- (IOSObjectArray *)getCrlOcspRefs {
  IOSObjectArray *result = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(self->crlOcspRefs_)) size] type:LibOrgBouncycastleAsn1EsfCrlOcspRef_class_()];
  for (jint idx = 0; idx < result->size_; idx++) {
    (void) IOSObjectArray_Set(result, idx, LibOrgBouncycastleAsn1EsfCrlOcspRef_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(self->crlOcspRefs_)) getObjectAtWithInt:idx]));
  }
  return result;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return self->crlOcspRefs_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1EsfCompleteRevocationRefs;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1EsfCrlOcspRef;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1EsfCrlOcspRefArray:);
  methods[3].selector = @selector(getCrlOcspRefs);
  methods[4].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "crlOcspRefs_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "[LLibOrgBouncycastleAsn1EsfCrlOcspRef;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EsfCompleteRevocationRefs = { "CompleteRevocationRefs", "lib.org.bouncycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EsfCompleteRevocationRefs;
}

@end

LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1EsfCompleteRevocationRefs class]]) {
    return (LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> seqEnum = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(seqEnum)) hasMoreElements]) {
    (void) LibOrgBouncycastleAsn1EsfCrlOcspRef_getInstanceWithId_([seqEnum nextElement]);
  }
  self->crlOcspRefs_ = seq;
}

LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *new_LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfCompleteRevocationRefs, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *create_LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfCompleteRevocationRefs, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1EsfCrlOcspRefArray_(LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *self, IOSObjectArray *crlOcspRefs) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->crlOcspRefs_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(crlOcspRefs);
}

LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *new_LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1EsfCrlOcspRefArray_(IOSObjectArray *crlOcspRefs) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfCompleteRevocationRefs, initWithLibOrgBouncycastleAsn1EsfCrlOcspRefArray_, crlOcspRefs)
}

LibOrgBouncycastleAsn1EsfCompleteRevocationRefs *create_LibOrgBouncycastleAsn1EsfCompleteRevocationRefs_initWithLibOrgBouncycastleAsn1EsfCrlOcspRefArray_(IOSObjectArray *crlOcspRefs) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfCompleteRevocationRefs, initWithLibOrgBouncycastleAsn1EsfCrlOcspRefArray_, crlOcspRefs)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EsfCompleteRevocationRefs)
