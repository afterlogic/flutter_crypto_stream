//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x9/X9ECPoint.java
//

#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "Arrays.h"
#include "DEROctetString.h"
#include "ECCurve.h"
#include "ECPoint.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "X9ECPoint.h"

@interface LibOrgBouncycastleAsn1X9X9ECPoint () {
 @public
  LibOrgBouncycastleAsn1ASN1OctetString *encoding_;
  LibOrgBouncycastleMathEcECCurve *c_;
  LibOrgBouncycastleMathEcECPoint *p_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9X9ECPoint, encoding_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9X9ECPoint, c_, LibOrgBouncycastleMathEcECCurve *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9X9ECPoint, p_, LibOrgBouncycastleMathEcECPoint *)

@implementation LibOrgBouncycastleAsn1X9X9ECPoint

- (instancetype)initWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p {
  LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECPoint_(self, p);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                            withBoolean:(jboolean)compressed {
  LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECPoint_withBoolean_(self, p, compressed);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)c
                                          withByteArray:(IOSByteArray *)encoding {
  LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECCurve_withByteArray_(self, c, encoding);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)c
              withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)s {
  LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleAsn1ASN1OctetString_(self, c, s);
  return self;
}

- (IOSByteArray *)getPointEncoding {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(encoding_)) getOctets]);
}

- (LibOrgBouncycastleMathEcECPoint *)getPoint {
  @synchronized(self) {
    if (p_ == nil) {
      p_ = [((LibOrgBouncycastleMathEcECPoint *) nil_chk([((LibOrgBouncycastleMathEcECCurve *) nil_chk(c_)) decodePointWithByteArray:[((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(encoding_)) getOctets]])) normalize];
    }
    return p_;
  }
}

- (jboolean)isPointCompressed {
  IOSByteArray *octets = [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(encoding_)) getOctets];
  return octets != nil && octets->size_ > 0 && (IOSByteArray_Get(octets, 0) == 2 || IOSByteArray_Get(octets, 0) == 3);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return encoding_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x21, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleMathEcECPoint:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleMathEcECPoint:withBoolean:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleMathEcECCurve:withByteArray:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleMathEcECCurve:withLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[4].selector = @selector(getPointEncoding);
  methods[5].selector = @selector(getPoint);
  methods[6].selector = @selector(isPointCompressed);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "encoding_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "c_", "LLibOrgBouncycastleMathEcECCurve;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "p_", "LLibOrgBouncycastleMathEcECPoint;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleMathEcECPoint;", "LLibOrgBouncycastleMathEcECPoint;Z", "LLibOrgBouncycastleMathEcECCurve;[B", "LLibOrgBouncycastleMathEcECCurve;LLibOrgBouncycastleAsn1ASN1OctetString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X9X9ECPoint = { "X9ECPoint", "lib.org.bouncycastle.asn1.x9", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X9X9ECPoint;
}

@end

void LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleAsn1X9X9ECPoint *self, LibOrgBouncycastleMathEcECPoint *p) {
  LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECPoint_withBoolean_(self, p, false);
}

LibOrgBouncycastleAsn1X9X9ECPoint *new_LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleMathEcECPoint *p) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9X9ECPoint, initWithLibOrgBouncycastleMathEcECPoint_, p)
}

LibOrgBouncycastleAsn1X9X9ECPoint *create_LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleMathEcECPoint *p) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9X9ECPoint, initWithLibOrgBouncycastleMathEcECPoint_, p)
}

void LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECPoint_withBoolean_(LibOrgBouncycastleAsn1X9X9ECPoint *self, LibOrgBouncycastleMathEcECPoint *p, jboolean compressed) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->p_ = [((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) normalize];
  self->encoding_ = new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_([p getEncodedWithBoolean:compressed]);
}

LibOrgBouncycastleAsn1X9X9ECPoint *new_LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECPoint_withBoolean_(LibOrgBouncycastleMathEcECPoint *p, jboolean compressed) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9X9ECPoint, initWithLibOrgBouncycastleMathEcECPoint_withBoolean_, p, compressed)
}

LibOrgBouncycastleAsn1X9X9ECPoint *create_LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECPoint_withBoolean_(LibOrgBouncycastleMathEcECPoint *p, jboolean compressed) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9X9ECPoint, initWithLibOrgBouncycastleMathEcECPoint_withBoolean_, p, compressed)
}

void LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECCurve_withByteArray_(LibOrgBouncycastleAsn1X9X9ECPoint *self, LibOrgBouncycastleMathEcECCurve *c, IOSByteArray *encoding) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->c_ = c;
  self->encoding_ = new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(LibOrgBouncycastleUtilArrays_cloneWithByteArray_(encoding));
}

LibOrgBouncycastleAsn1X9X9ECPoint *new_LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECCurve_withByteArray_(LibOrgBouncycastleMathEcECCurve *c, IOSByteArray *encoding) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9X9ECPoint, initWithLibOrgBouncycastleMathEcECCurve_withByteArray_, c, encoding)
}

LibOrgBouncycastleAsn1X9X9ECPoint *create_LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECCurve_withByteArray_(LibOrgBouncycastleMathEcECCurve *c, IOSByteArray *encoding) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9X9ECPoint, initWithLibOrgBouncycastleMathEcECCurve_withByteArray_, c, encoding)
}

void LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1X9X9ECPoint *self, LibOrgBouncycastleMathEcECCurve *c, LibOrgBouncycastleAsn1ASN1OctetString *s) {
  LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECCurve_withByteArray_(self, c, [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(s)) getOctets]);
}

LibOrgBouncycastleAsn1X9X9ECPoint *new_LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleMathEcECCurve *c, LibOrgBouncycastleAsn1ASN1OctetString *s) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9X9ECPoint, initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleAsn1ASN1OctetString_, c, s)
}

LibOrgBouncycastleAsn1X9X9ECPoint *create_LibOrgBouncycastleAsn1X9X9ECPoint_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleMathEcECCurve *c, LibOrgBouncycastleAsn1ASN1OctetString *s) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9X9ECPoint, initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleAsn1ASN1OctetString_, c, s)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X9X9ECPoint)
