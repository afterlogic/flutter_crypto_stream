//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/CMPCertificate.java
//

#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "AttributeCertificate.h"
#include "CMPCertificate.h"
#include "DERTaggedObject.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "X509Certificate.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmpCMPCertificate () {
 @public
  LibOrgBouncycastleAsn1X509X509Certificate *x509v3PKCert_;
  jint otherTagValue_;
  LibOrgBouncycastleAsn1ASN1Object *otherCert_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpCMPCertificate, x509v3PKCert_, LibOrgBouncycastleAsn1X509X509Certificate *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpCMPCertificate, otherCert_, LibOrgBouncycastleAsn1ASN1Object *)

@implementation LibOrgBouncycastleAsn1CmpCMPCertificate

- (instancetype)initWithLibOrgBouncycastleAsn1X509AttributeCertificate:(LibOrgBouncycastleAsn1X509AttributeCertificate *)x509v2AttrCert {
  LibOrgBouncycastleAsn1CmpCMPCertificate_initWithLibOrgBouncycastleAsn1X509AttributeCertificate_(self, x509v2AttrCert);
  return self;
}

- (instancetype)initWithInt:(jint)type
withLibOrgBouncycastleAsn1ASN1Object:(LibOrgBouncycastleAsn1ASN1Object *)otherCert {
  LibOrgBouncycastleAsn1CmpCMPCertificate_initWithInt_withLibOrgBouncycastleAsn1ASN1Object_(self, type, otherCert);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509X509Certificate:(LibOrgBouncycastleAsn1X509X509Certificate *)x509v3PKCert {
  LibOrgBouncycastleAsn1CmpCMPCertificate_initWithLibOrgBouncycastleAsn1X509X509Certificate_(self, x509v3PKCert);
  return self;
}

+ (LibOrgBouncycastleAsn1CmpCMPCertificate *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmpCMPCertificate_getInstanceWithId_(o);
}

- (jboolean)isX509v3PKCert {
  return x509v3PKCert_ != nil;
}

- (LibOrgBouncycastleAsn1X509X509Certificate *)getX509v3PKCert {
  return x509v3PKCert_;
}

- (LibOrgBouncycastleAsn1X509AttributeCertificate *)getX509v2AttrCert {
  return LibOrgBouncycastleAsn1X509AttributeCertificate_getInstanceWithId_(otherCert_);
}

- (jint)getOtherCertTag {
  return otherTagValue_;
}

- (LibOrgBouncycastleAsn1ASN1Object *)getOtherCert {
  return otherCert_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  if (otherCert_ != nil) {
    return new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, otherTagValue_, otherCert_);
  }
  return [((LibOrgBouncycastleAsn1X509X509Certificate *) nil_chk(x509v3PKCert_)) toASN1Primitive];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpCMPCertificate;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509X509Certificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AttributeCertificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Object;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1X509AttributeCertificate:);
  methods[1].selector = @selector(initWithInt:withLibOrgBouncycastleAsn1ASN1Object:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1X509X509Certificate:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(isX509v3PKCert);
  methods[5].selector = @selector(getX509v3PKCert);
  methods[6].selector = @selector(getX509v2AttrCert);
  methods[7].selector = @selector(getOtherCertTag);
  methods[8].selector = @selector(getOtherCert);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "x509v3PKCert_", "LLibOrgBouncycastleAsn1X509X509Certificate;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "otherTagValue_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "otherCert_", "LLibOrgBouncycastleAsn1ASN1Object;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1X509AttributeCertificate;", "ILLibOrgBouncycastleAsn1ASN1Object;", "LLibOrgBouncycastleAsn1X509X509Certificate;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpCMPCertificate = { "CMPCertificate", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpCMPCertificate;
}

@end

void LibOrgBouncycastleAsn1CmpCMPCertificate_initWithLibOrgBouncycastleAsn1X509AttributeCertificate_(LibOrgBouncycastleAsn1CmpCMPCertificate *self, LibOrgBouncycastleAsn1X509AttributeCertificate *x509v2AttrCert) {
  LibOrgBouncycastleAsn1CmpCMPCertificate_initWithInt_withLibOrgBouncycastleAsn1ASN1Object_(self, 1, x509v2AttrCert);
}

LibOrgBouncycastleAsn1CmpCMPCertificate *new_LibOrgBouncycastleAsn1CmpCMPCertificate_initWithLibOrgBouncycastleAsn1X509AttributeCertificate_(LibOrgBouncycastleAsn1X509AttributeCertificate *x509v2AttrCert) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpCMPCertificate, initWithLibOrgBouncycastleAsn1X509AttributeCertificate_, x509v2AttrCert)
}

LibOrgBouncycastleAsn1CmpCMPCertificate *create_LibOrgBouncycastleAsn1CmpCMPCertificate_initWithLibOrgBouncycastleAsn1X509AttributeCertificate_(LibOrgBouncycastleAsn1X509AttributeCertificate *x509v2AttrCert) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpCMPCertificate, initWithLibOrgBouncycastleAsn1X509AttributeCertificate_, x509v2AttrCert)
}

void LibOrgBouncycastleAsn1CmpCMPCertificate_initWithInt_withLibOrgBouncycastleAsn1ASN1Object_(LibOrgBouncycastleAsn1CmpCMPCertificate *self, jint type, LibOrgBouncycastleAsn1ASN1Object *otherCert) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->otherTagValue_ = type;
  self->otherCert_ = otherCert;
}

LibOrgBouncycastleAsn1CmpCMPCertificate *new_LibOrgBouncycastleAsn1CmpCMPCertificate_initWithInt_withLibOrgBouncycastleAsn1ASN1Object_(jint type, LibOrgBouncycastleAsn1ASN1Object *otherCert) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpCMPCertificate, initWithInt_withLibOrgBouncycastleAsn1ASN1Object_, type, otherCert)
}

LibOrgBouncycastleAsn1CmpCMPCertificate *create_LibOrgBouncycastleAsn1CmpCMPCertificate_initWithInt_withLibOrgBouncycastleAsn1ASN1Object_(jint type, LibOrgBouncycastleAsn1ASN1Object *otherCert) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpCMPCertificate, initWithInt_withLibOrgBouncycastleAsn1ASN1Object_, type, otherCert)
}

void LibOrgBouncycastleAsn1CmpCMPCertificate_initWithLibOrgBouncycastleAsn1X509X509Certificate_(LibOrgBouncycastleAsn1CmpCMPCertificate *self, LibOrgBouncycastleAsn1X509X509Certificate *x509v3PKCert) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1X509X509Certificate *) nil_chk(x509v3PKCert)) getVersionNumber] != 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"only version 3 certificates allowed");
  }
  self->x509v3PKCert_ = x509v3PKCert;
}

LibOrgBouncycastleAsn1CmpCMPCertificate *new_LibOrgBouncycastleAsn1CmpCMPCertificate_initWithLibOrgBouncycastleAsn1X509X509Certificate_(LibOrgBouncycastleAsn1X509X509Certificate *x509v3PKCert) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpCMPCertificate, initWithLibOrgBouncycastleAsn1X509X509Certificate_, x509v3PKCert)
}

LibOrgBouncycastleAsn1CmpCMPCertificate *create_LibOrgBouncycastleAsn1CmpCMPCertificate_initWithLibOrgBouncycastleAsn1X509X509Certificate_(LibOrgBouncycastleAsn1X509X509Certificate *x509v3PKCert) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpCMPCertificate, initWithLibOrgBouncycastleAsn1X509X509Certificate_, x509v3PKCert)
}

LibOrgBouncycastleAsn1CmpCMPCertificate *LibOrgBouncycastleAsn1CmpCMPCertificate_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmpCMPCertificate_initialize();
  if (o == nil || [o isKindOfClass:[LibOrgBouncycastleAsn1CmpCMPCertificate class]]) {
    return (LibOrgBouncycastleAsn1CmpCMPCertificate *) cast_chk(o, [LibOrgBouncycastleAsn1CmpCMPCertificate class]);
  }
  if ([o isKindOfClass:[IOSByteArray class]]) {
    @try {
      o = LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_((IOSByteArray *) cast_chk(o, [IOSByteArray class]));
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Invalid encoding in CMPCertificate");
    }
  }
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return new_LibOrgBouncycastleAsn1CmpCMPCertificate_initWithLibOrgBouncycastleAsn1X509X509Certificate_(LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithId_(o));
  }
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *taggedObject = (LibOrgBouncycastleAsn1ASN1TaggedObject *) o;
    return new_LibOrgBouncycastleAsn1CmpCMPCertificate_initWithInt_withLibOrgBouncycastleAsn1ASN1Object_([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(taggedObject)) getTagNo], [taggedObject getObject]);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid object: ", [[nil_chk(o) java_getClass] getName]));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpCMPCertificate)