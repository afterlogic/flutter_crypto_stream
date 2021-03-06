//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/smime/SMIMECapabilityVector.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1ObjectIdentifier.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "SMIMECapabilityVector.h"

@interface LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector () {
 @public
  LibOrgBouncycastleAsn1ASN1EncodableVector *capabilities_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector, capabilities_, LibOrgBouncycastleAsn1ASN1EncodableVector *)

@implementation LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)addCapabilityWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)capability {
  [((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(capabilities_)) addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(capability)];
}

- (void)addCapabilityWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)capability
                                                            withInt:(jint)value {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:capability];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(value)];
  [((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(capabilities_)) addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v)];
}

- (void)addCapabilityWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)capability
                            withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)params {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:capability];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:params];
  [((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(capabilities_)) addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v)];
}

- (LibOrgBouncycastleAsn1ASN1EncodableVector *)toASN1EncodableVector {
  return capabilities_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1EncodableVector;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(addCapabilityWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[2].selector = @selector(addCapabilityWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withInt:);
  methods[3].selector = @selector(addCapabilityWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[4].selector = @selector(toASN1EncodableVector);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "capabilities_", "LLibOrgBouncycastleAsn1ASN1EncodableVector;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "addCapability", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;I", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector = { "SMIMECapabilityVector", "lib.org.bouncycastle.asn1.smime", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector;
}

@end

void LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector_init(LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector *self) {
  NSObject_init(self);
  self->capabilities_ = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
}

LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector *new_LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector, init)
}

LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector *create_LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1SmimeSMIMECapabilityVector)
