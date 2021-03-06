//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ocsp/ResponseBytes.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "ResponseBytes.h"

@implementation LibOrgBouncycastleAsn1OcspResponseBytes

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)responseType
                         withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)response {
  LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(self, responseType, response);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1OcspResponseBytes *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                       withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1OcspResponseBytes_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1OcspResponseBytes *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1OcspResponseBytes_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getResponseType {
  return responseType_;
}

- (LibOrgBouncycastleAsn1ASN1OctetString *)getResponse {
  return response_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:responseType_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:response_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspResponseBytes;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspResponseBytes;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getResponseType);
  methods[5].selector = @selector(getResponse);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "responseType_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "response_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1OctetString;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1OcspResponseBytes = { "ResponseBytes", "lib.org.bouncycastle.asn1.ocsp", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1OcspResponseBytes;
}

@end

void LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1OcspResponseBytes *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *responseType, LibOrgBouncycastleAsn1ASN1OctetString *response) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->responseType_ = responseType;
  self->response_ = response;
}

LibOrgBouncycastleAsn1OcspResponseBytes *new_LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *responseType, LibOrgBouncycastleAsn1ASN1OctetString *response) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspResponseBytes, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_, responseType, response)
}

LibOrgBouncycastleAsn1OcspResponseBytes *create_LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *responseType, LibOrgBouncycastleAsn1ASN1OctetString *response) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspResponseBytes, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_, responseType, response)
}

void LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1OcspResponseBytes *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->responseType_ = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
  self->response_ = (LibOrgBouncycastleAsn1ASN1OctetString *) cast_chk([seq getObjectAtWithInt:1], [LibOrgBouncycastleAsn1ASN1OctetString class]);
}

LibOrgBouncycastleAsn1OcspResponseBytes *new_LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1OcspResponseBytes, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1OcspResponseBytes *create_LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1OcspResponseBytes, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1OcspResponseBytes *LibOrgBouncycastleAsn1OcspResponseBytes_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1OcspResponseBytes_initialize();
  return LibOrgBouncycastleAsn1OcspResponseBytes_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1OcspResponseBytes *LibOrgBouncycastleAsn1OcspResponseBytes_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1OcspResponseBytes_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1OcspResponseBytes class]]) {
    return (LibOrgBouncycastleAsn1OcspResponseBytes *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1OcspResponseBytes_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1OcspResponseBytes)
