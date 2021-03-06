//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/util/DEROtherInfo.java
//

#include "ASN1EncodableVector.h"
#include "ASN1OctetString.h"
#include "ASN1TaggedObject.h"
#include "AlgorithmIdentifier.h"
#include "DEROtherInfo.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "DerUtil.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleCryptoUtilDEROtherInfo () {
 @public
  LibOrgBouncycastleAsn1DERSequence *sequence_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1DERSequence:(LibOrgBouncycastleAsn1DERSequence *)sequence;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoUtilDEROtherInfo, sequence_, LibOrgBouncycastleAsn1DERSequence *)

__attribute__((unused)) static void LibOrgBouncycastleCryptoUtilDEROtherInfo_initWithLibOrgBouncycastleAsn1DERSequence_(LibOrgBouncycastleCryptoUtilDEROtherInfo *self, LibOrgBouncycastleAsn1DERSequence *sequence);

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilDEROtherInfo *new_LibOrgBouncycastleCryptoUtilDEROtherInfo_initWithLibOrgBouncycastleAsn1DERSequence_(LibOrgBouncycastleAsn1DERSequence *sequence) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoUtilDEROtherInfo *create_LibOrgBouncycastleCryptoUtilDEROtherInfo_initWithLibOrgBouncycastleAsn1DERSequence_(LibOrgBouncycastleAsn1DERSequence *sequence);

@interface LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder () {
 @public
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmID_;
  LibOrgBouncycastleAsn1ASN1OctetString *partyUVInfo_;
  LibOrgBouncycastleAsn1ASN1OctetString *partyVInfo_;
  LibOrgBouncycastleAsn1ASN1TaggedObject *suppPubInfo_;
  LibOrgBouncycastleAsn1ASN1TaggedObject *suppPrivInfo_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder, algorithmID_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder, partyUVInfo_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder, partyVInfo_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder, suppPubInfo_, LibOrgBouncycastleAsn1ASN1TaggedObject *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder, suppPrivInfo_, LibOrgBouncycastleAsn1ASN1TaggedObject *)

@implementation LibOrgBouncycastleCryptoUtilDEROtherInfo

- (instancetype)initWithLibOrgBouncycastleAsn1DERSequence:(LibOrgBouncycastleAsn1DERSequence *)sequence {
  LibOrgBouncycastleCryptoUtilDEROtherInfo_initWithLibOrgBouncycastleAsn1DERSequence_(self, sequence);
  return self;
}

- (IOSByteArray *)getEncoded {
  return [((LibOrgBouncycastleAsn1DERSequence *) nil_chk(sequence_)) getEncoded];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1DERSequence:);
  methods[1].selector = @selector(getEncoded);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "sequence_", "LLibOrgBouncycastleAsn1DERSequence;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1DERSequence;", "LJavaIoIOException;", "LLibOrgBouncycastleCryptoUtilDEROtherInfo_Builder;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoUtilDEROtherInfo = { "DEROtherInfo", "lib.org.bouncycastle.crypto.util", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, 2, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoUtilDEROtherInfo;
}

@end

void LibOrgBouncycastleCryptoUtilDEROtherInfo_initWithLibOrgBouncycastleAsn1DERSequence_(LibOrgBouncycastleCryptoUtilDEROtherInfo *self, LibOrgBouncycastleAsn1DERSequence *sequence) {
  NSObject_init(self);
  self->sequence_ = sequence;
}

LibOrgBouncycastleCryptoUtilDEROtherInfo *new_LibOrgBouncycastleCryptoUtilDEROtherInfo_initWithLibOrgBouncycastleAsn1DERSequence_(LibOrgBouncycastleAsn1DERSequence *sequence) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoUtilDEROtherInfo, initWithLibOrgBouncycastleAsn1DERSequence_, sequence)
}

LibOrgBouncycastleCryptoUtilDEROtherInfo *create_LibOrgBouncycastleCryptoUtilDEROtherInfo_initWithLibOrgBouncycastleAsn1DERSequence_(LibOrgBouncycastleAsn1DERSequence *sequence) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoUtilDEROtherInfo, initWithLibOrgBouncycastleAsn1DERSequence_, sequence)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoUtilDEROtherInfo)

@implementation LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)algorithmID
                                                        withByteArray:(IOSByteArray *)partyUInfo
                                                        withByteArray:(IOSByteArray *)partyVInfo {
  LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(self, algorithmID, partyUInfo, partyVInfo);
  return self;
}

- (LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder *)withSuppPubInfoWithByteArray:(IOSByteArray *)suppPubInfo {
  self->suppPubInfo_ = new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 0, LibOrgBouncycastleCryptoUtilDerUtil_getOctetStringWithByteArray_(suppPubInfo));
  return self;
}

- (LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder *)withSuppPrivInfoWithByteArray:(IOSByteArray *)suppPrivInfo {
  self->suppPrivInfo_ = new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 1, LibOrgBouncycastleCryptoUtilDerUtil_getOctetStringWithByteArray_(suppPrivInfo));
  return self;
}

- (LibOrgBouncycastleCryptoUtilDEROtherInfo *)build {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:algorithmID_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:partyUVInfo_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:partyVInfo_];
  if (suppPubInfo_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:suppPubInfo_];
  }
  if (suppPrivInfo_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:suppPrivInfo_];
  }
  return new_LibOrgBouncycastleCryptoUtilDEROtherInfo_initWithLibOrgBouncycastleAsn1DERSequence_(new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoUtilDEROtherInfo_Builder;", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoUtilDEROtherInfo_Builder;", 0x1, 3, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoUtilDEROtherInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:withByteArray:withByteArray:);
  methods[1].selector = @selector(withSuppPubInfoWithByteArray:);
  methods[2].selector = @selector(withSuppPrivInfoWithByteArray:);
  methods[3].selector = @selector(build);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "algorithmID_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "partyUVInfo_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "partyVInfo_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "suppPubInfo_", "LLibOrgBouncycastleAsn1ASN1TaggedObject;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "suppPrivInfo_", "LLibOrgBouncycastleAsn1ASN1TaggedObject;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;[B[B", "withSuppPubInfo", "[B", "withSuppPrivInfo", "LLibOrgBouncycastleCryptoUtilDEROtherInfo;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder = { "Builder", "lib.org.bouncycastle.crypto.util", ptrTable, methods, fields, 7, 0x19, 4, 5, 4, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder;
}

@end

void LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmID, IOSByteArray *partyUInfo, IOSByteArray *partyVInfo) {
  NSObject_init(self);
  self->algorithmID_ = algorithmID;
  self->partyUVInfo_ = LibOrgBouncycastleCryptoUtilDerUtil_getOctetStringWithByteArray_(partyUInfo);
  self->partyVInfo_ = LibOrgBouncycastleCryptoUtilDerUtil_getOctetStringWithByteArray_(partyVInfo);
}

LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder *new_LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmID, IOSByteArray *partyUInfo, IOSByteArray *partyVInfo) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_, algorithmID, partyUInfo, partyVInfo)
}

LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder *create_LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *algorithmID, IOSByteArray *partyUInfo, IOSByteArray *partyVInfo) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_withByteArray_, algorithmID, partyUInfo, partyVInfo)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoUtilDEROtherInfo_Builder)
