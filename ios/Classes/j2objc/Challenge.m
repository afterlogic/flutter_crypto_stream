//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/Challenge.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "AlgorithmIdentifier.h"
#include "Challenge.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleAsn1CmpChallenge () {
 @public
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf_;
  LibOrgBouncycastleAsn1ASN1OctetString *witness_;
  LibOrgBouncycastleAsn1ASN1OctetString *challenge_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (void)addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v
                         withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpChallenge, owf_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpChallenge, witness_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpChallenge, challenge_, LibOrgBouncycastleAsn1ASN1OctetString *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpChallenge *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpChallenge *new_LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpChallenge *create_LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpChallenge_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmpChallenge *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

@implementation LibOrgBouncycastleAsn1CmpChallenge

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmpChallenge *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1CmpChallenge_getInstanceWithId_(o);
}

- (instancetype)initWithByteArray:(IOSByteArray *)witness
                    withByteArray:(IOSByteArray *)challenge {
  LibOrgBouncycastleAsn1CmpChallenge_initWithByteArray_withByteArray_(self, witness, challenge);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)owf
                                                        withByteArray:(IOSByteArray *)witness
                                                        withByteArray:(IOSByteArray *)challenge {
  LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(self, owf, witness, challenge);
  return self;
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getOwf {
  return owf_;
}

- (IOSByteArray *)getWitness {
  return [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(witness_)) getOctets];
}

- (IOSByteArray *)getChallenge {
  return [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(challenge_)) getOctets];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  LibOrgBouncycastleAsn1CmpChallenge_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, owf_);
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:witness_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:challenge_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

- (void)addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v
                         withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj {
  LibOrgBouncycastleAsn1CmpChallenge_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, obj);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpChallenge;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithByteArray:withByteArray:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withByteArray:withByteArray:);
  methods[4].selector = @selector(getOwf);
  methods[5].selector = @selector(getWitness);
  methods[6].selector = @selector(getChallenge);
  methods[7].selector = @selector(toASN1Primitive);
  methods[8].selector = @selector(addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:withLibOrgBouncycastleAsn1ASN1Encodable:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "owf_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "witness_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "challenge_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "[B[B", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;[B[B", "addOptional", "LLibOrgBouncycastleAsn1ASN1EncodableVector;LLibOrgBouncycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpChallenge = { "Challenge", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 9, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpChallenge;
}

@end

void LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmpChallenge *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  jint index = 0;
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] == 3) {
    self->owf_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([seq getObjectAtWithInt:index++]);
  }
  self->witness_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:index++]);
  self->challenge_ = LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:index]);
}

LibOrgBouncycastleAsn1CmpChallenge *new_LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpChallenge, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpChallenge *create_LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpChallenge, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmpChallenge *LibOrgBouncycastleAsn1CmpChallenge_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1CmpChallenge_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1CmpChallenge class]]) {
    return (LibOrgBouncycastleAsn1CmpChallenge *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmpChallenge_initWithByteArray_withByteArray_(LibOrgBouncycastleAsn1CmpChallenge *self, IOSByteArray *witness, IOSByteArray *challenge) {
  LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(self, nil, witness, challenge);
}

LibOrgBouncycastleAsn1CmpChallenge *new_LibOrgBouncycastleAsn1CmpChallenge_initWithByteArray_withByteArray_(IOSByteArray *witness, IOSByteArray *challenge) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpChallenge, initWithByteArray_withByteArray_, witness, challenge)
}

LibOrgBouncycastleAsn1CmpChallenge *create_LibOrgBouncycastleAsn1CmpChallenge_initWithByteArray_withByteArray_(IOSByteArray *witness, IOSByteArray *challenge) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpChallenge, initWithByteArray_withByteArray_, witness, challenge)
}

void LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(LibOrgBouncycastleAsn1CmpChallenge *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, IOSByteArray *witness, IOSByteArray *challenge) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->owf_ = owf;
  self->witness_ = new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(witness);
  self->challenge_ = new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(challenge);
}

LibOrgBouncycastleAsn1CmpChallenge *new_LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, IOSByteArray *witness, IOSByteArray *challenge) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpChallenge, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_, owf, witness, challenge)
}

LibOrgBouncycastleAsn1CmpChallenge *create_LibOrgBouncycastleAsn1CmpChallenge_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *owf, IOSByteArray *witness, IOSByteArray *challenge) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpChallenge, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_, owf, witness, challenge)
}

void LibOrgBouncycastleAsn1CmpChallenge_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmpChallenge *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v, id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  if (obj != nil) {
    [((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(v)) addWithLibOrgBouncycastleAsn1ASN1Encodable:obj];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpChallenge)
