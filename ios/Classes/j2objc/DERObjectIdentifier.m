//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DERObjectIdentifier.java
//

#include "ASN1ObjectIdentifier.h"
#include "DERObjectIdentifier.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"

@implementation LibOrgBouncycastleAsn1DERObjectIdentifier

- (instancetype)initWithNSString:(NSString *)identifier {
  LibOrgBouncycastleAsn1DERObjectIdentifier_initWithNSString_(self, identifier);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)bytes {
  LibOrgBouncycastleAsn1DERObjectIdentifier_initWithByteArray_(self, bytes);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                      withNSString:(NSString *)branch {
  LibOrgBouncycastleAsn1DERObjectIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withNSString_(self, oid, branch);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(initWithByteArray:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LNSString;", "[B", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1DERObjectIdentifier = { "DERObjectIdentifier", "lib.org.bouncycastle.asn1", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1DERObjectIdentifier;
}

@end

void LibOrgBouncycastleAsn1DERObjectIdentifier_initWithNSString_(LibOrgBouncycastleAsn1DERObjectIdentifier *self, NSString *identifier) {
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(self, identifier);
}

LibOrgBouncycastleAsn1DERObjectIdentifier *new_LibOrgBouncycastleAsn1DERObjectIdentifier_initWithNSString_(NSString *identifier) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DERObjectIdentifier, initWithNSString_, identifier)
}

LibOrgBouncycastleAsn1DERObjectIdentifier *create_LibOrgBouncycastleAsn1DERObjectIdentifier_initWithNSString_(NSString *identifier) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DERObjectIdentifier, initWithNSString_, identifier)
}

void LibOrgBouncycastleAsn1DERObjectIdentifier_initWithByteArray_(LibOrgBouncycastleAsn1DERObjectIdentifier *self, IOSByteArray *bytes) {
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithByteArray_(self, bytes);
}

LibOrgBouncycastleAsn1DERObjectIdentifier *new_LibOrgBouncycastleAsn1DERObjectIdentifier_initWithByteArray_(IOSByteArray *bytes) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DERObjectIdentifier, initWithByteArray_, bytes)
}

LibOrgBouncycastleAsn1DERObjectIdentifier *create_LibOrgBouncycastleAsn1DERObjectIdentifier_initWithByteArray_(IOSByteArray *bytes) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DERObjectIdentifier, initWithByteArray_, bytes)
}

void LibOrgBouncycastleAsn1DERObjectIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withNSString_(LibOrgBouncycastleAsn1DERObjectIdentifier *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, NSString *branch) {
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withNSString_(self, oid, branch);
}

LibOrgBouncycastleAsn1DERObjectIdentifier *new_LibOrgBouncycastleAsn1DERObjectIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withNSString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, NSString *branch) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DERObjectIdentifier, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withNSString_, oid, branch)
}

LibOrgBouncycastleAsn1DERObjectIdentifier *create_LibOrgBouncycastleAsn1DERObjectIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withNSString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, NSString *branch) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DERObjectIdentifier, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withNSString_, oid, branch)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1DERObjectIdentifier)
