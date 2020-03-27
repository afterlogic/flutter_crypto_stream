//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/eac/UnsignedInteger.java
//

#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1TaggedObject.h"
#include "DEROctetString.h"
#include "DERTaggedObject.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "UnsignedInteger.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1EacUnsignedInteger () {
 @public
  jint tagNo_;
  JavaMathBigInteger *value_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj;

- (IOSByteArray *)convertValue;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EacUnsignedInteger, value_, JavaMathBigInteger *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EacUnsignedInteger_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1EacUnsignedInteger *self, LibOrgBouncycastleAsn1ASN1TaggedObject *obj);

__attribute__((unused)) static LibOrgBouncycastleAsn1EacUnsignedInteger *new_LibOrgBouncycastleAsn1EacUnsignedInteger_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EacUnsignedInteger *create_LibOrgBouncycastleAsn1EacUnsignedInteger_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj);

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleAsn1EacUnsignedInteger_convertValue(LibOrgBouncycastleAsn1EacUnsignedInteger *self);

@implementation LibOrgBouncycastleAsn1EacUnsignedInteger

- (instancetype)initWithInt:(jint)tagNo
     withJavaMathBigInteger:(JavaMathBigInteger *)value {
  LibOrgBouncycastleAsn1EacUnsignedInteger_initWithInt_withJavaMathBigInteger_(self, tagNo, value);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj {
  LibOrgBouncycastleAsn1EacUnsignedInteger_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(self, obj);
  return self;
}

+ (LibOrgBouncycastleAsn1EacUnsignedInteger *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EacUnsignedInteger_getInstanceWithId_(obj);
}

- (IOSByteArray *)convertValue {
  return LibOrgBouncycastleAsn1EacUnsignedInteger_convertValue(self);
}

- (jint)getTagNo {
  return tagNo_;
}

- (JavaMathBigInteger *)getValue {
  return value_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, tagNo_, new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(LibOrgBouncycastleAsn1EacUnsignedInteger_convertValue(self)));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EacUnsignedInteger;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withJavaMathBigInteger:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1TaggedObject:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(convertValue);
  methods[4].selector = @selector(getTagNo);
  methods[5].selector = @selector(getValue);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "tagNo_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "value_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILJavaMathBigInteger;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EacUnsignedInteger = { "UnsignedInteger", "lib.org.bouncycastle.asn1.eac", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EacUnsignedInteger;
}

@end

void LibOrgBouncycastleAsn1EacUnsignedInteger_initWithInt_withJavaMathBigInteger_(LibOrgBouncycastleAsn1EacUnsignedInteger *self, jint tagNo, JavaMathBigInteger *value) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = tagNo;
  self->value_ = value;
}

LibOrgBouncycastleAsn1EacUnsignedInteger *new_LibOrgBouncycastleAsn1EacUnsignedInteger_initWithInt_withJavaMathBigInteger_(jint tagNo, JavaMathBigInteger *value) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EacUnsignedInteger, initWithInt_withJavaMathBigInteger_, tagNo, value)
}

LibOrgBouncycastleAsn1EacUnsignedInteger *create_LibOrgBouncycastleAsn1EacUnsignedInteger_initWithInt_withJavaMathBigInteger_(jint tagNo, JavaMathBigInteger *value) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EacUnsignedInteger, initWithInt_withJavaMathBigInteger_, tagNo, value)
}

void LibOrgBouncycastleAsn1EacUnsignedInteger_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1EacUnsignedInteger *self, LibOrgBouncycastleAsn1ASN1TaggedObject *obj) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->tagNo_ = [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getTagNo];
  self->value_ = new_JavaMathBigInteger_initWithInt_withByteArray_(1, [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, false))) getOctets]);
}

LibOrgBouncycastleAsn1EacUnsignedInteger *new_LibOrgBouncycastleAsn1EacUnsignedInteger_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EacUnsignedInteger, initWithLibOrgBouncycastleAsn1ASN1TaggedObject_, obj)
}

LibOrgBouncycastleAsn1EacUnsignedInteger *create_LibOrgBouncycastleAsn1EacUnsignedInteger_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EacUnsignedInteger, initWithLibOrgBouncycastleAsn1ASN1TaggedObject_, obj)
}

LibOrgBouncycastleAsn1EacUnsignedInteger *LibOrgBouncycastleAsn1EacUnsignedInteger_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EacUnsignedInteger_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1EacUnsignedInteger class]]) {
    return (LibOrgBouncycastleAsn1EacUnsignedInteger *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1EacUnsignedInteger_initWithLibOrgBouncycastleAsn1ASN1TaggedObject_(LibOrgBouncycastleAsn1ASN1TaggedObject_getInstanceWithId_(obj));
  }
  return nil;
}

IOSByteArray *LibOrgBouncycastleAsn1EacUnsignedInteger_convertValue(LibOrgBouncycastleAsn1EacUnsignedInteger *self) {
  IOSByteArray *v = [((JavaMathBigInteger *) nil_chk(self->value_)) toByteArray];
  if (IOSByteArray_Get(nil_chk(v), 0) == 0) {
    IOSByteArray *tmp = [IOSByteArray newArrayWithLength:v->size_ - 1];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(v, 1, tmp, 0, tmp->size_);
    return tmp;
  }
  return v;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EacUnsignedInteger)