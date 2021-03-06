//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/ProtectedPart.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "PKIBody.h"
#include "PKIHeader.h"
#include "ProtectedPart.h"

@interface LibOrgBouncycastleAsn1CmpProtectedPart () {
 @public
  LibOrgBouncycastleAsn1CmpPKIHeader *header_;
  LibOrgBouncycastleAsn1CmpPKIBody *body_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpProtectedPart, header_, LibOrgBouncycastleAsn1CmpPKIHeader *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpProtectedPart, body_, LibOrgBouncycastleAsn1CmpPKIBody *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpProtectedPart *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpProtectedPart *new_LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpProtectedPart *create_LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmpProtectedPart

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmpProtectedPart *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmpProtectedPart_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmpPKIHeader:(LibOrgBouncycastleAsn1CmpPKIHeader *)header
                      withLibOrgBouncycastleAsn1CmpPKIBody:(LibOrgBouncycastleAsn1CmpPKIBody *)body {
  LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1CmpPKIHeader_withLibOrgBouncycastleAsn1CmpPKIBody_(self, header, body);
  return self;
}

- (LibOrgBouncycastleAsn1CmpPKIHeader *)getHeader {
  return header_;
}

- (LibOrgBouncycastleAsn1CmpPKIBody *)getBody {
  return body_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:header_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:body_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpProtectedPart;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeader;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIBody;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1CmpPKIHeader:withLibOrgBouncycastleAsn1CmpPKIBody:);
  methods[3].selector = @selector(getHeader);
  methods[4].selector = @selector(getBody);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "header_", "LLibOrgBouncycastleAsn1CmpPKIHeader;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "body_", "LLibOrgBouncycastleAsn1CmpPKIBody;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1CmpPKIHeader;LLibOrgBouncycastleAsn1CmpPKIBody;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpProtectedPart = { "ProtectedPart", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpProtectedPart;
}

@end

void LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpProtectedPart *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->header_ = LibOrgBouncycastleAsn1CmpPKIHeader_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->body_ = LibOrgBouncycastleAsn1CmpPKIBody_getInstanceWithId_([seq getObjectAtWithInt:1]);
}

LibOrgBouncycastleAsn1CmpProtectedPart *new_LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpProtectedPart, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpProtectedPart *create_LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpProtectedPart, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpProtectedPart *LibOrgBouncycastleAsn1CmpProtectedPart_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmpProtectedPart_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmpProtectedPart class]]) {
    return (LibOrgBouncycastleAsn1CmpProtectedPart *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1CmpPKIHeader_withLibOrgBouncycastleAsn1CmpPKIBody_(LibOrgBouncycastleAsn1CmpProtectedPart *self, LibOrgBouncycastleAsn1CmpPKIHeader *header, LibOrgBouncycastleAsn1CmpPKIBody *body) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->header_ = header;
  self->body_ = body;
}

LibOrgBouncycastleAsn1CmpProtectedPart *new_LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1CmpPKIHeader_withLibOrgBouncycastleAsn1CmpPKIBody_(LibOrgBouncycastleAsn1CmpPKIHeader *header, LibOrgBouncycastleAsn1CmpPKIBody *body) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpProtectedPart, initWithLibOrgBouncycastleAsn1CmpPKIHeader_withLibOrgBouncycastleAsn1CmpPKIBody_, header, body)
}

LibOrgBouncycastleAsn1CmpProtectedPart *create_LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1CmpPKIHeader_withLibOrgBouncycastleAsn1CmpPKIBody_(LibOrgBouncycastleAsn1CmpPKIHeader *header, LibOrgBouncycastleAsn1CmpPKIBody *body) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpProtectedPart, initWithLibOrgBouncycastleAsn1CmpPKIHeader_withLibOrgBouncycastleAsn1CmpPKIBody_, header, body)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpProtectedPart)
