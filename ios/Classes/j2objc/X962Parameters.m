//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x9/X962Parameters.java
//

#include "ASN1Null.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1TaggedObject.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "X962Parameters.h"
#include "X9ECParameters.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1X9X962Parameters () {
 @public
  LibOrgBouncycastleAsn1ASN1Primitive *params_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9X962Parameters, params_, LibOrgBouncycastleAsn1ASN1Primitive *)

@implementation LibOrgBouncycastleAsn1X9X962Parameters

+ (LibOrgBouncycastleAsn1X9X962Parameters *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X9X962Parameters_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1X9X962Parameters *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1X9X962Parameters_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithLibOrgBouncycastleAsn1X9X9ECParameters:(LibOrgBouncycastleAsn1X9X9ECParameters *)ecParameters {
  LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1X9X9ECParameters_(self, ecParameters);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)namedCurve {
  LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, namedCurve);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Null:(LibOrgBouncycastleAsn1ASN1Null *)obj {
  LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Null_(self, obj);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)obj {
  LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Primitive_(self, obj);
  return self;
}

- (jboolean)isNamedCurve {
  return ([params_ isKindOfClass:[LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]]);
}

- (jboolean)isImplicitlyCA {
  return ([params_ isKindOfClass:[LibOrgBouncycastleAsn1ASN1Null class]]);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)getParameters {
  return params_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return params_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X9X962Parameters;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X9X962Parameters;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 6, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1X9X9ECParameters:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Null:);
  methods[5].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Primitive:);
  methods[6].selector = @selector(isNamedCurve);
  methods[7].selector = @selector(isImplicitlyCA);
  methods[8].selector = @selector(getParameters);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastleAsn1ASN1Primitive;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LLibOrgBouncycastleAsn1X9X9ECParameters;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "LLibOrgBouncycastleAsn1ASN1Null;", "LLibOrgBouncycastleAsn1ASN1Primitive;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X9X962Parameters = { "X962Parameters", "lib.org.bouncycastle.asn1.x9", ptrTable, methods, fields, 7, 0x1, 10, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X9X962Parameters;
}

@end

LibOrgBouncycastleAsn1X9X962Parameters *LibOrgBouncycastleAsn1X9X962Parameters_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X9X962Parameters_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1X9X962Parameters class]]) {
    return (LibOrgBouncycastleAsn1X9X962Parameters *) cast_chk(obj, [LibOrgBouncycastleAsn1X9X962Parameters class]);
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Primitive class]]) {
    return new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Primitive_((LibOrgBouncycastleAsn1ASN1Primitive *) obj);
  }
  if ([obj isKindOfClass:[IOSByteArray class]]) {
    @try {
      return new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_((IOSByteArray *) cast_chk(obj, [IOSByteArray class])));
    }
    @catch (JavaLangException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"unable to parse encoded data: ", [e getMessage]));
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown object in getInstance()");
}

LibOrgBouncycastleAsn1X9X962Parameters *LibOrgBouncycastleAsn1X9X962Parameters_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1X9X962Parameters_initialize();
  return LibOrgBouncycastleAsn1X9X962Parameters_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getObject]);
}

void LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1X9X9ECParameters_(LibOrgBouncycastleAsn1X9X962Parameters *self, LibOrgBouncycastleAsn1X9X9ECParameters *ecParameters) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->params_ = nil;
  self->params_ = [((LibOrgBouncycastleAsn1X9X9ECParameters *) nil_chk(ecParameters)) toASN1Primitive];
}

LibOrgBouncycastleAsn1X9X962Parameters *new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1X9X9ECParameters_(LibOrgBouncycastleAsn1X9X9ECParameters *ecParameters) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9X962Parameters, initWithLibOrgBouncycastleAsn1X9X9ECParameters_, ecParameters)
}

LibOrgBouncycastleAsn1X9X962Parameters *create_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1X9X9ECParameters_(LibOrgBouncycastleAsn1X9X9ECParameters *ecParameters) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9X962Parameters, initWithLibOrgBouncycastleAsn1X9X9ECParameters_, ecParameters)
}

void LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1X9X962Parameters *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurve) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->params_ = nil;
  self->params_ = namedCurve;
}

LibOrgBouncycastleAsn1X9X962Parameters *new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurve) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9X962Parameters, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, namedCurve)
}

LibOrgBouncycastleAsn1X9X962Parameters *create_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurve) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9X962Parameters, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, namedCurve)
}

void LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Null_(LibOrgBouncycastleAsn1X9X962Parameters *self, LibOrgBouncycastleAsn1ASN1Null *obj) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->params_ = nil;
  self->params_ = obj;
}

LibOrgBouncycastleAsn1X9X962Parameters *new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Null_(LibOrgBouncycastleAsn1ASN1Null *obj) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9X962Parameters, initWithLibOrgBouncycastleAsn1ASN1Null_, obj)
}

LibOrgBouncycastleAsn1X9X962Parameters *create_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Null_(LibOrgBouncycastleAsn1ASN1Null *obj) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9X962Parameters, initWithLibOrgBouncycastleAsn1ASN1Null_, obj)
}

void LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1X9X962Parameters *self, LibOrgBouncycastleAsn1ASN1Primitive *obj) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->params_ = nil;
  self->params_ = obj;
}

LibOrgBouncycastleAsn1X9X962Parameters *new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1ASN1Primitive *obj) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9X962Parameters, initWithLibOrgBouncycastleAsn1ASN1Primitive_, obj)
}

LibOrgBouncycastleAsn1X9X962Parameters *create_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1ASN1Primitive *obj) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9X962Parameters, initWithLibOrgBouncycastleAsn1ASN1Primitive_, obj)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X9X962Parameters)
