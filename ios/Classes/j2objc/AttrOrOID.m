//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/est/AttrOrOID.java
//

#include "ASN1Encodable.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "AttrOrOID.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PkcsAttribute.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1EstAttrOrOID () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid_;
  LibOrgBouncycastleAsn1PkcsPkcsAttribute *attribute_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EstAttrOrOID, oid_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EstAttrOrOID, attribute_, LibOrgBouncycastleAsn1PkcsPkcsAttribute *)

@implementation LibOrgBouncycastleAsn1EstAttrOrOID

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid {
  LibOrgBouncycastleAsn1EstAttrOrOID_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, oid);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1PkcsPkcsAttribute:(LibOrgBouncycastleAsn1PkcsPkcsAttribute *)attribute {
  LibOrgBouncycastleAsn1EstAttrOrOID_initWithLibOrgBouncycastleAsn1PkcsPkcsAttribute_(self, attribute);
  return self;
}

+ (LibOrgBouncycastleAsn1EstAttrOrOID *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EstAttrOrOID_getInstanceWithId_(obj);
}

- (jboolean)isOid {
  return oid_ != nil;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getOid {
  return oid_;
}

- (LibOrgBouncycastleAsn1PkcsPkcsAttribute *)getAttribute {
  return attribute_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  if (oid_ != nil) {
    return oid_;
  }
  return [((LibOrgBouncycastleAsn1PkcsPkcsAttribute *) nil_chk(attribute_)) toASN1Primitive];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EstAttrOrOID;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1PkcsPkcsAttribute;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1PkcsPkcsAttribute:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(isOid);
  methods[4].selector = @selector(getOid);
  methods[5].selector = @selector(getAttribute);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "oid_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "attribute_", "LLibOrgBouncycastleAsn1PkcsPkcsAttribute;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "LLibOrgBouncycastleAsn1PkcsPkcsAttribute;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EstAttrOrOID = { "AttrOrOID", "lib.org.bouncycastle.asn1.est", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EstAttrOrOID;
}

@end

void LibOrgBouncycastleAsn1EstAttrOrOID_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1EstAttrOrOID *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->oid_ = oid;
  self->attribute_ = nil;
}

LibOrgBouncycastleAsn1EstAttrOrOID *new_LibOrgBouncycastleAsn1EstAttrOrOID_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EstAttrOrOID, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, oid)
}

LibOrgBouncycastleAsn1EstAttrOrOID *create_LibOrgBouncycastleAsn1EstAttrOrOID_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EstAttrOrOID, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, oid)
}

void LibOrgBouncycastleAsn1EstAttrOrOID_initWithLibOrgBouncycastleAsn1PkcsPkcsAttribute_(LibOrgBouncycastleAsn1EstAttrOrOID *self, LibOrgBouncycastleAsn1PkcsPkcsAttribute *attribute) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->oid_ = nil;
  self->attribute_ = attribute;
}

LibOrgBouncycastleAsn1EstAttrOrOID *new_LibOrgBouncycastleAsn1EstAttrOrOID_initWithLibOrgBouncycastleAsn1PkcsPkcsAttribute_(LibOrgBouncycastleAsn1PkcsPkcsAttribute *attribute) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EstAttrOrOID, initWithLibOrgBouncycastleAsn1PkcsPkcsAttribute_, attribute)
}

LibOrgBouncycastleAsn1EstAttrOrOID *create_LibOrgBouncycastleAsn1EstAttrOrOID_initWithLibOrgBouncycastleAsn1PkcsPkcsAttribute_(LibOrgBouncycastleAsn1PkcsPkcsAttribute *attribute) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EstAttrOrOID, initWithLibOrgBouncycastleAsn1PkcsPkcsAttribute_, attribute)
}

LibOrgBouncycastleAsn1EstAttrOrOID *LibOrgBouncycastleAsn1EstAttrOrOID_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EstAttrOrOID_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1EstAttrOrOID class]]) {
    return (LibOrgBouncycastleAsn1EstAttrOrOID *) obj;
  }
  if (obj != nil) {
    if ([LibOrgBouncycastleAsn1ASN1Encodable_class_() isInstance:obj]) {
      id<LibOrgBouncycastleAsn1ASN1Encodable> asn1Prim = [((id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check(obj, LibOrgBouncycastleAsn1ASN1Encodable_class_())) toASN1Primitive];
      if ([asn1Prim isKindOfClass:[LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]]) {
        return new_LibOrgBouncycastleAsn1EstAttrOrOID_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_(asn1Prim));
      }
      if ([asn1Prim isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
        return new_LibOrgBouncycastleAsn1EstAttrOrOID_initWithLibOrgBouncycastleAsn1PkcsPkcsAttribute_(LibOrgBouncycastleAsn1PkcsPkcsAttribute_getInstanceWithId_(asn1Prim));
      }
    }
    if ([obj isKindOfClass:[IOSByteArray class]]) {
      @try {
        return LibOrgBouncycastleAsn1EstAttrOrOID_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_((IOSByteArray *) cast_chk(obj, [IOSByteArray class])));
      }
      @catch (JavaIoIOException *e) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown encoding in getInstance()");
      }
    }
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"unknown object in getInstance(): ", [[obj java_getClass] getName]));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EstAttrOrOID)