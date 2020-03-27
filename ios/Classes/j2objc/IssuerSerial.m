//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/IssuerSerial.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERBitString.h"
#include "DERSequence.h"
#include "GeneralName.h"
#include "GeneralNames.h"
#include "IssuerSerial.h"
#include "J2ObjC_source.h"
#include "X500Name.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1X509IssuerSerial ()

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509IssuerSerial *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X509IssuerSerial *new_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X509IssuerSerial *create_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1X509IssuerSerial

+ (LibOrgBouncycastleAsn1X509IssuerSerial *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X509IssuerSerial_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1X509IssuerSerial *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1X509IssuerSerial_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)issuer
                                    withJavaMathBigInteger:(JavaMathBigInteger *)serial {
  LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_(self, issuer, serial);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509GeneralNames:(LibOrgBouncycastleAsn1X509GeneralNames *)issuer
                                        withJavaMathBigInteger:(JavaMathBigInteger *)serial {
  LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withJavaMathBigInteger_(self, issuer, serial);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509GeneralNames:(LibOrgBouncycastleAsn1X509GeneralNames *)issuer
                         withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)serial {
  LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withLibOrgBouncycastleAsn1ASN1Integer_(self, issuer, serial);
  return self;
}

- (LibOrgBouncycastleAsn1X509GeneralNames *)getIssuer {
  return issuer_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getSerial {
  return serial_;
}

- (LibOrgBouncycastleAsn1DERBitString *)getIssuerUID {
  return issuerUID_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:issuer_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:serial_];
  if (issuerUID_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:issuerUID_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X509IssuerSerial;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509IssuerSerial;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509GeneralNames;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERBitString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1X500X500Name:withJavaMathBigInteger:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1X509GeneralNames:withJavaMathBigInteger:);
  methods[5].selector = @selector(initWithLibOrgBouncycastleAsn1X509GeneralNames:withLibOrgBouncycastleAsn1ASN1Integer:);
  methods[6].selector = @selector(getIssuer);
  methods[7].selector = @selector(getSerial);
  methods[8].selector = @selector(getIssuerUID);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "issuer_", "LLibOrgBouncycastleAsn1X509GeneralNames;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "serial_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "issuerUID_", "LLibOrgBouncycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1X500X500Name;LJavaMathBigInteger;", "LLibOrgBouncycastleAsn1X509GeneralNames;LJavaMathBigInteger;", "LLibOrgBouncycastleAsn1X509GeneralNames;LLibOrgBouncycastleAsn1ASN1Integer;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X509IssuerSerial = { "IssuerSerial", "lib.org.bouncycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X509IssuerSerial;
}

@end

LibOrgBouncycastleAsn1X509IssuerSerial *LibOrgBouncycastleAsn1X509IssuerSerial_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X509IssuerSerial_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1X509IssuerSerial class]]) {
    return (LibOrgBouncycastleAsn1X509IssuerSerial *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

LibOrgBouncycastleAsn1X509IssuerSerial *LibOrgBouncycastleAsn1X509IssuerSerial_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1X509IssuerSerial_initialize();
  return LibOrgBouncycastleAsn1X509IssuerSerial_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

void LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509IssuerSerial *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2 && [seq size] != 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  self->issuer_ = LibOrgBouncycastleAsn1X509GeneralNames_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->serial_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:1]);
  if ([seq size] == 3) {
    self->issuerUID_ = LibOrgBouncycastleAsn1DERBitString_getInstanceWithId_([seq getObjectAtWithInt:2]);
  }
}

LibOrgBouncycastleAsn1X509IssuerSerial *new_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509IssuerSerial, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X509IssuerSerial *create_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509IssuerSerial, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509IssuerSerial *self, LibOrgBouncycastleAsn1X500X500Name *issuer, JavaMathBigInteger *serial) {
  LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withLibOrgBouncycastleAsn1ASN1Integer_(self, new_LibOrgBouncycastleAsn1X509GeneralNames_initWithLibOrgBouncycastleAsn1X509GeneralName_(new_LibOrgBouncycastleAsn1X509GeneralName_initWithLibOrgBouncycastleAsn1X500X500Name_(issuer)), new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(serial));
}

LibOrgBouncycastleAsn1X509IssuerSerial *new_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X500X500Name *issuer, JavaMathBigInteger *serial) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509IssuerSerial, initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_, issuer, serial)
}

LibOrgBouncycastleAsn1X509IssuerSerial *create_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X500X500Name *issuer, JavaMathBigInteger *serial) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509IssuerSerial, initWithLibOrgBouncycastleAsn1X500X500Name_withJavaMathBigInteger_, issuer, serial)
}

void LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509IssuerSerial *self, LibOrgBouncycastleAsn1X509GeneralNames *issuer, JavaMathBigInteger *serial) {
  LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withLibOrgBouncycastleAsn1ASN1Integer_(self, issuer, new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(serial));
}

LibOrgBouncycastleAsn1X509IssuerSerial *new_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509GeneralNames *issuer, JavaMathBigInteger *serial) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509IssuerSerial, initWithLibOrgBouncycastleAsn1X509GeneralNames_withJavaMathBigInteger_, issuer, serial)
}

LibOrgBouncycastleAsn1X509IssuerSerial *create_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withJavaMathBigInteger_(LibOrgBouncycastleAsn1X509GeneralNames *issuer, JavaMathBigInteger *serial) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509IssuerSerial, initWithLibOrgBouncycastleAsn1X509GeneralNames_withJavaMathBigInteger_, issuer, serial)
}

void LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X509IssuerSerial *self, LibOrgBouncycastleAsn1X509GeneralNames *issuer, LibOrgBouncycastleAsn1ASN1Integer *serial) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->issuer_ = issuer;
  self->serial_ = serial;
}

LibOrgBouncycastleAsn1X509IssuerSerial *new_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X509GeneralNames *issuer, LibOrgBouncycastleAsn1ASN1Integer *serial) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X509IssuerSerial, initWithLibOrgBouncycastleAsn1X509GeneralNames_withLibOrgBouncycastleAsn1ASN1Integer_, issuer, serial)
}

LibOrgBouncycastleAsn1X509IssuerSerial *create_LibOrgBouncycastleAsn1X509IssuerSerial_initWithLibOrgBouncycastleAsn1X509GeneralNames_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X509GeneralNames *issuer, LibOrgBouncycastleAsn1ASN1Integer *serial) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X509IssuerSerial, initWithLibOrgBouncycastleAsn1X509GeneralNames_withLibOrgBouncycastleAsn1ASN1Integer_, issuer, serial)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X509IssuerSerial)