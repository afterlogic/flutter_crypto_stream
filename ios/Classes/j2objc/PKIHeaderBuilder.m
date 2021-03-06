//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/PKIHeaderBuilder.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1GeneralizedTime.h"
#include "ASN1Integer.h"
#include "ASN1OctetString.h"
#include "ASN1Sequence.h"
#include "AlgorithmIdentifier.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "GeneralName.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "InfoTypeAndValue.h"
#include "J2ObjC_source.h"
#include "PKIFreeText.h"
#include "PKIHeader.h"
#include "PKIHeaderBuilder.h"

@interface LibOrgBouncycastleAsn1CmpPKIHeaderBuilder () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *pvno_;
  LibOrgBouncycastleAsn1X509GeneralName *sender_;
  LibOrgBouncycastleAsn1X509GeneralName *recipient_;
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *messageTime_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *protectionAlg_;
  LibOrgBouncycastleAsn1ASN1OctetString *senderKID_;
  LibOrgBouncycastleAsn1ASN1OctetString *recipKID_;
  LibOrgBouncycastleAsn1ASN1OctetString *transactionID_;
  LibOrgBouncycastleAsn1ASN1OctetString *senderNonce_;
  LibOrgBouncycastleAsn1ASN1OctetString *recipNonce_;
  LibOrgBouncycastleAsn1CmpPKIFreeText *freeText_;
  LibOrgBouncycastleAsn1ASN1Sequence *generalInfo_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)pvno
                withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)sender
                withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)recipient;

+ (LibOrgBouncycastleAsn1ASN1Sequence *)makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue:(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *)generalInfo;

+ (LibOrgBouncycastleAsn1ASN1Sequence *)makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray:(IOSObjectArray *)generalInfos;

- (void)addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v
                                                         withInt:(jint)tagNo
                         withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, pvno_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, sender_, LibOrgBouncycastleAsn1X509GeneralName *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, recipient_, LibOrgBouncycastleAsn1X509GeneralName *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, messageTime_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, protectionAlg_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, senderKID_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, recipKID_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, transactionID_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, senderNonce_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, recipNonce_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, freeText_, LibOrgBouncycastleAsn1CmpPKIFreeText *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, generalInfo_, LibOrgBouncycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *self, LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *new_LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *create_LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient);

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1Sequence *LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue_(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *generalInfo);

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1Sequence *LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray_(IOSObjectArray *generalInfos);

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

@implementation LibOrgBouncycastleAsn1CmpPKIHeaderBuilder

- (instancetype)initWithInt:(jint)pvno
withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)sender
withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)recipient {
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(self, pvno, sender, recipient);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)pvno
                withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)sender
                withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)recipient {
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(self, pvno, sender, recipient);
  return self;
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setMessageTimeWithLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)time {
  messageTime_ = time;
  return self;
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setProtectionAlgWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)aid {
  protectionAlg_ = aid;
  return self;
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setSenderKIDWithByteArray:(IOSByteArray *)kid {
  return [self setSenderKIDWithLibOrgBouncycastleAsn1ASN1OctetString:kid == nil ? nil : new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(kid)];
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setSenderKIDWithLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)kid {
  senderKID_ = kid;
  return self;
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setRecipKIDWithByteArray:(IOSByteArray *)kid {
  return [self setRecipKIDWithLibOrgBouncycastleAsn1DEROctetString:kid == nil ? nil : new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(kid)];
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setRecipKIDWithLibOrgBouncycastleAsn1DEROctetString:(LibOrgBouncycastleAsn1DEROctetString *)kid {
  recipKID_ = kid;
  return self;
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setTransactionIDWithByteArray:(IOSByteArray *)tid {
  return [self setTransactionIDWithLibOrgBouncycastleAsn1ASN1OctetString:tid == nil ? nil : new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(tid)];
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setTransactionIDWithLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)tid {
  transactionID_ = tid;
  return self;
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setSenderNonceWithByteArray:(IOSByteArray *)nonce {
  return [self setSenderNonceWithLibOrgBouncycastleAsn1ASN1OctetString:nonce == nil ? nil : new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(nonce)];
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setSenderNonceWithLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)nonce {
  senderNonce_ = nonce;
  return self;
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setRecipNonceWithByteArray:(IOSByteArray *)nonce {
  return [self setRecipNonceWithLibOrgBouncycastleAsn1ASN1OctetString:nonce == nil ? nil : new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(nonce)];
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setRecipNonceWithLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)nonce {
  recipNonce_ = nonce;
  return self;
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setFreeTextWithLibOrgBouncycastleAsn1CmpPKIFreeText:(LibOrgBouncycastleAsn1CmpPKIFreeText *)text {
  freeText_ = text;
  return self;
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setGeneralInfoWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue:(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *)genInfo {
  return [self setGeneralInfoWithLibOrgBouncycastleAsn1ASN1Sequence:LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue_(genInfo)];
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setGeneralInfoWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray:(IOSObjectArray *)genInfos {
  return [self setGeneralInfoWithLibOrgBouncycastleAsn1ASN1Sequence:LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray_(genInfos)];
}

- (LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *)setGeneralInfoWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seqOfInfoTypeAndValue {
  generalInfo_ = seqOfInfoTypeAndValue;
  return self;
}

+ (LibOrgBouncycastleAsn1ASN1Sequence *)makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue:(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *)generalInfo {
  return LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue_(generalInfo);
}

+ (LibOrgBouncycastleAsn1ASN1Sequence *)makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray:(IOSObjectArray *)generalInfos {
  return LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray_(generalInfos);
}

- (LibOrgBouncycastleAsn1CmpPKIHeader *)build {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:pvno_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:sender_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:recipient_];
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 0, messageTime_);
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 1, protectionAlg_);
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 2, senderKID_);
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 3, recipKID_);
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 4, transactionID_);
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 5, senderNonce_);
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 6, recipNonce_);
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 7, freeText_);
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, 8, generalInfo_);
  messageTime_ = nil;
  protectionAlg_ = nil;
  senderKID_ = nil;
  recipKID_ = nil;
  transactionID_ = nil;
  senderNonce_ = nil;
  recipNonce_ = nil;
  freeText_ = nil;
  generalInfo_ = nil;
  return LibOrgBouncycastleAsn1CmpPKIHeader_getInstanceWithId_(new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v));
}

- (void)addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)v
                                                         withInt:(jint)tagNo
                         withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj {
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(self, v, tagNo, obj);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 6, 8, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 9, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 9, 10, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 11, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 11, 8, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 12, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 12, 8, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 13, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 13, 8, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 14, 15, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 16, 17, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 16, 18, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeaderBuilder;", 0x1, 16, 19, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Sequence;", 0xa, 20, 17, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Sequence;", 0xa, 20, 18, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIHeader;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 21, 22, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withLibOrgBouncycastleAsn1X509GeneralName:withLibOrgBouncycastleAsn1X509GeneralName:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1X509GeneralName:withLibOrgBouncycastleAsn1X509GeneralName:);
  methods[2].selector = @selector(setMessageTimeWithLibOrgBouncycastleAsn1ASN1GeneralizedTime:);
  methods[3].selector = @selector(setProtectionAlgWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:);
  methods[4].selector = @selector(setSenderKIDWithByteArray:);
  methods[5].selector = @selector(setSenderKIDWithLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[6].selector = @selector(setRecipKIDWithByteArray:);
  methods[7].selector = @selector(setRecipKIDWithLibOrgBouncycastleAsn1DEROctetString:);
  methods[8].selector = @selector(setTransactionIDWithByteArray:);
  methods[9].selector = @selector(setTransactionIDWithLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[10].selector = @selector(setSenderNonceWithByteArray:);
  methods[11].selector = @selector(setSenderNonceWithLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[12].selector = @selector(setRecipNonceWithByteArray:);
  methods[13].selector = @selector(setRecipNonceWithLibOrgBouncycastleAsn1ASN1OctetString:);
  methods[14].selector = @selector(setFreeTextWithLibOrgBouncycastleAsn1CmpPKIFreeText:);
  methods[15].selector = @selector(setGeneralInfoWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue:);
  methods[16].selector = @selector(setGeneralInfoWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray:);
  methods[17].selector = @selector(setGeneralInfoWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[18].selector = @selector(makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue:);
  methods[19].selector = @selector(makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray:);
  methods[20].selector = @selector(build);
  methods[21].selector = @selector(addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector:withInt:withLibOrgBouncycastleAsn1ASN1Encodable:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "pvno_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sender_", "LLibOrgBouncycastleAsn1X509GeneralName;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "recipient_", "LLibOrgBouncycastleAsn1X509GeneralName;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "messageTime_", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "protectionAlg_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "senderKID_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "recipKID_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "transactionID_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "senderNonce_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "recipNonce_", "LLibOrgBouncycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "freeText_", "LLibOrgBouncycastleAsn1CmpPKIFreeText;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "generalInfo_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILLibOrgBouncycastleAsn1X509GeneralName;LLibOrgBouncycastleAsn1X509GeneralName;", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1X509GeneralName;LLibOrgBouncycastleAsn1X509GeneralName;", "setMessageTime", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", "setProtectionAlg", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", "setSenderKID", "[B", "LLibOrgBouncycastleAsn1ASN1OctetString;", "setRecipKID", "LLibOrgBouncycastleAsn1DEROctetString;", "setTransactionID", "setSenderNonce", "setRecipNonce", "setFreeText", "LLibOrgBouncycastleAsn1CmpPKIFreeText;", "setGeneralInfo", "LLibOrgBouncycastleAsn1CmpInfoTypeAndValue;", "[LLibOrgBouncycastleAsn1CmpInfoTypeAndValue;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "makeGeneralInfoSeq", "addOptional", "LLibOrgBouncycastleAsn1ASN1EncodableVector;ILLibOrgBouncycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmpPKIHeaderBuilder = { "PKIHeaderBuilder", "lib.org.bouncycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 22, 12, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmpPKIHeaderBuilder;
}

@end

void LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *self, jint pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(self, new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(pvno), sender, recipient);
}

LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *new_LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(jint pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_, pvno, sender, recipient)
}

LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *create_LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(jint pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, initWithInt_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_, pvno, sender, recipient)
}

void LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *self, LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  NSObject_init(self);
  self->pvno_ = pvno;
  self->sender_ = sender;
  self->recipient_ = recipient;
}

LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *new_LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_, pvno, sender, recipient)
}

LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *create_LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_(LibOrgBouncycastleAsn1ASN1Integer *pvno, LibOrgBouncycastleAsn1X509GeneralName *sender, LibOrgBouncycastleAsn1X509GeneralName *recipient) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509GeneralName_, pvno, sender, recipient)
}

LibOrgBouncycastleAsn1ASN1Sequence *LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValue_(LibOrgBouncycastleAsn1CmpInfoTypeAndValue *generalInfo) {
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initialize();
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(generalInfo);
}

LibOrgBouncycastleAsn1ASN1Sequence *LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_makeGeneralInfoSeqWithLibOrgBouncycastleAsn1CmpInfoTypeAndValueArray_(IOSObjectArray *generalInfos) {
  LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_initialize();
  LibOrgBouncycastleAsn1ASN1Sequence *genInfoSeq = nil;
  if (generalInfos != nil) {
    LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
    for (jint i = 0; i < generalInfos->size_; i++) {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:IOSObjectArray_Get(generalInfos, i)];
    }
    genInfoSeq = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
  }
  return genInfoSeq;
}

void LibOrgBouncycastleAsn1CmpPKIHeaderBuilder_addOptionalWithLibOrgBouncycastleAsn1ASN1EncodableVector_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder *self, LibOrgBouncycastleAsn1ASN1EncodableVector *v, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj) {
  if (obj != nil) {
    [((LibOrgBouncycastleAsn1ASN1EncodableVector *) nil_chk(v)) addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, tagNo, obj)];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmpPKIHeaderBuilder)
