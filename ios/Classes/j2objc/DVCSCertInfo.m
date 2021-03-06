//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/dvcs/DVCSCertInfo.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1Set.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "DVCSCertInfo.h"
#include "DVCSRequestInformation.h"
#include "DVCSTime.h"
#include "DigestInfo.h"
#include "Extensions.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "PKIStatusInfo.h"
#include "PolicyInformation.h"
#include "TargetEtcChain.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/StringBuffer.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1DvcsDVCSCertInfo () {
 @public
  jint version__;
  LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *dvReqInfo_;
  LibOrgBouncycastleAsn1X509DigestInfo *messageImprint_;
  LibOrgBouncycastleAsn1ASN1Integer *serialNumber_;
  LibOrgBouncycastleAsn1DvcsDVCSTime *responseTime_;
  LibOrgBouncycastleAsn1CmpPKIStatusInfo *dvStatus_;
  LibOrgBouncycastleAsn1X509PolicyInformation *policy_;
  LibOrgBouncycastleAsn1ASN1Set *reqSignature_;
  LibOrgBouncycastleAsn1ASN1Sequence *certs_;
  LibOrgBouncycastleAsn1X509Extensions *extensions_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (void)setVersionWithInt:(jint)version_;

- (void)setDvReqInfoWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation:(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *)dvReqInfo;

- (void)setMessageImprintWithLibOrgBouncycastleAsn1X509DigestInfo:(LibOrgBouncycastleAsn1X509DigestInfo *)messageImprint;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, dvReqInfo_, LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, messageImprint_, LibOrgBouncycastleAsn1X509DigestInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, serialNumber_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, responseTime_, LibOrgBouncycastleAsn1DvcsDVCSTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, dvStatus_, LibOrgBouncycastleAsn1CmpPKIStatusInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, policy_, LibOrgBouncycastleAsn1X509PolicyInformation *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, reqSignature_, LibOrgBouncycastleAsn1ASN1Set *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, certs_, LibOrgBouncycastleAsn1ASN1Sequence *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, extensions_, LibOrgBouncycastleAsn1X509Extensions *)

inline jint LibOrgBouncycastleAsn1DvcsDVCSCertInfo_get_DEFAULT_VERSION(void);
#define LibOrgBouncycastleAsn1DvcsDVCSCertInfo_DEFAULT_VERSION 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, DEFAULT_VERSION, jint)

inline jint LibOrgBouncycastleAsn1DvcsDVCSCertInfo_get_TAG_DV_STATUS(void);
#define LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_DV_STATUS 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, TAG_DV_STATUS, jint)

inline jint LibOrgBouncycastleAsn1DvcsDVCSCertInfo_get_TAG_POLICY(void);
#define LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_POLICY 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, TAG_POLICY, jint)

inline jint LibOrgBouncycastleAsn1DvcsDVCSCertInfo_get_TAG_REQ_SIGNATURE(void);
#define LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_REQ_SIGNATURE 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, TAG_REQ_SIGNATURE, jint)

inline jint LibOrgBouncycastleAsn1DvcsDVCSCertInfo_get_TAG_CERTS(void);
#define LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_CERTS 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, TAG_CERTS, jint)

__attribute__((unused)) static void LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1DvcsDVCSCertInfo *new_LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1DvcsDVCSCertInfo *create_LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static void LibOrgBouncycastleAsn1DvcsDVCSCertInfo_setVersionWithInt_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *self, jint version_);

__attribute__((unused)) static void LibOrgBouncycastleAsn1DvcsDVCSCertInfo_setDvReqInfoWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *self, LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *dvReqInfo);

__attribute__((unused)) static void LibOrgBouncycastleAsn1DvcsDVCSCertInfo_setMessageImprintWithLibOrgBouncycastleAsn1X509DigestInfo_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *self, LibOrgBouncycastleAsn1X509DigestInfo *messageImprint);

@implementation LibOrgBouncycastleAsn1DvcsDVCSCertInfo

- (instancetype)initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation:(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *)dvReqInfo
                                withLibOrgBouncycastleAsn1X509DigestInfo:(LibOrgBouncycastleAsn1X509DigestInfo *)messageImprint
                                   withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)serialNumber
                                  withLibOrgBouncycastleAsn1DvcsDVCSTime:(LibOrgBouncycastleAsn1DvcsDVCSTime *)responseTime {
  LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_withLibOrgBouncycastleAsn1X509DigestInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1DvcsDVCSTime_(self, dvReqInfo, messageImprint, serialNumber, responseTime);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1DvcsDVCSCertInfo *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1DvcsDVCSCertInfo_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1DvcsDVCSCertInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1DvcsDVCSCertInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  if (version__ != LibOrgBouncycastleAsn1DvcsDVCSCertInfo_DEFAULT_VERSION) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(version__)];
  }
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:dvReqInfo_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:messageImprint_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:serialNumber_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:responseTime_];
  if (dvStatus_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_DV_STATUS, dvStatus_)];
  }
  if (policy_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_POLICY, policy_)];
  }
  if (reqSignature_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_REQ_SIGNATURE, reqSignature_)];
  }
  if (certs_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_CERTS, certs_)];
  }
  if (extensions_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:extensions_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

- (NSString *)description {
  JavaLangStringBuffer *s = new_JavaLangStringBuffer_init();
  (void) [s appendWithNSString:@"DVCSCertInfo {\n"];
  if (version__ != LibOrgBouncycastleAsn1DvcsDVCSCertInfo_DEFAULT_VERSION) {
    (void) [s appendWithNSString:JreStrcat("$IC", @"version: ", version__, 0x000a)];
  }
  (void) [s appendWithNSString:JreStrcat("$@C", @"dvReqInfo: ", dvReqInfo_, 0x000a)];
  (void) [s appendWithNSString:JreStrcat("$@C", @"messageImprint: ", messageImprint_, 0x000a)];
  (void) [s appendWithNSString:JreStrcat("$@C", @"serialNumber: ", serialNumber_, 0x000a)];
  (void) [s appendWithNSString:JreStrcat("$@C", @"responseTime: ", responseTime_, 0x000a)];
  if (dvStatus_ != nil) {
    (void) [s appendWithNSString:JreStrcat("$@C", @"dvStatus: ", dvStatus_, 0x000a)];
  }
  if (policy_ != nil) {
    (void) [s appendWithNSString:JreStrcat("$@C", @"policy: ", policy_, 0x000a)];
  }
  if (reqSignature_ != nil) {
    (void) [s appendWithNSString:JreStrcat("$@C", @"reqSignature: ", reqSignature_, 0x000a)];
  }
  if (certs_ != nil) {
    (void) [s appendWithNSString:JreStrcat("$@C", @"certs: ", certs_, 0x000a)];
  }
  if (extensions_ != nil) {
    (void) [s appendWithNSString:JreStrcat("$@C", @"extensions: ", extensions_, 0x000a)];
  }
  (void) [s appendWithNSString:@"}\n"];
  return [s description];
}

- (jint)getVersion {
  return version__;
}

- (void)setVersionWithInt:(jint)version_ {
  LibOrgBouncycastleAsn1DvcsDVCSCertInfo_setVersionWithInt_(self, version_);
}

- (LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *)getDvReqInfo {
  return dvReqInfo_;
}

- (void)setDvReqInfoWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation:(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *)dvReqInfo {
  LibOrgBouncycastleAsn1DvcsDVCSCertInfo_setDvReqInfoWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_(self, dvReqInfo);
}

- (LibOrgBouncycastleAsn1X509DigestInfo *)getMessageImprint {
  return messageImprint_;
}

- (void)setMessageImprintWithLibOrgBouncycastleAsn1X509DigestInfo:(LibOrgBouncycastleAsn1X509DigestInfo *)messageImprint {
  LibOrgBouncycastleAsn1DvcsDVCSCertInfo_setMessageImprintWithLibOrgBouncycastleAsn1X509DigestInfo_(self, messageImprint);
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getSerialNumber {
  return serialNumber_;
}

- (LibOrgBouncycastleAsn1DvcsDVCSTime *)getResponseTime {
  return responseTime_;
}

- (LibOrgBouncycastleAsn1CmpPKIStatusInfo *)getDvStatus {
  return dvStatus_;
}

- (LibOrgBouncycastleAsn1X509PolicyInformation *)getPolicy {
  return policy_;
}

- (LibOrgBouncycastleAsn1ASN1Set *)getReqSignature {
  return reqSignature_;
}

- (IOSObjectArray *)getCerts {
  if (certs_ != nil) {
    return LibOrgBouncycastleAsn1DvcsTargetEtcChain_arrayFromSequenceWithLibOrgBouncycastleAsn1ASN1Sequence_(certs_);
  }
  return nil;
}

- (LibOrgBouncycastleAsn1X509Extensions *)getExtensions {
  return extensions_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DvcsDVCSCertInfo;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DvcsDVCSCertInfo;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 5, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DvcsDVCSRequestInformation;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 8, 9, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509DigestInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 10, 11, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DvcsDVCSTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmpPKIStatusInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509PolicyInformation;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1DvcsTargetEtcChain;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation:withLibOrgBouncycastleAsn1X509DigestInfo:withLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1DvcsDVCSTime:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[4].selector = @selector(toASN1Primitive);
  methods[5].selector = @selector(description);
  methods[6].selector = @selector(getVersion);
  methods[7].selector = @selector(setVersionWithInt:);
  methods[8].selector = @selector(getDvReqInfo);
  methods[9].selector = @selector(setDvReqInfoWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation:);
  methods[10].selector = @selector(getMessageImprint);
  methods[11].selector = @selector(setMessageImprintWithLibOrgBouncycastleAsn1X509DigestInfo:);
  methods[12].selector = @selector(getSerialNumber);
  methods[13].selector = @selector(getResponseTime);
  methods[14].selector = @selector(getDvStatus);
  methods[15].selector = @selector(getPolicy);
  methods[16].selector = @selector(getReqSignature);
  methods[17].selector = @selector(getCerts);
  methods[18].selector = @selector(getExtensions);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "I", .constantValue.asLong = 0, 0x2, 12, -1, -1, -1 },
    { "dvReqInfo_", "LLibOrgBouncycastleAsn1DvcsDVCSRequestInformation;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "messageImprint_", "LLibOrgBouncycastleAsn1X509DigestInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "serialNumber_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "responseTime_", "LLibOrgBouncycastleAsn1DvcsDVCSTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dvStatus_", "LLibOrgBouncycastleAsn1CmpPKIStatusInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "policy_", "LLibOrgBouncycastleAsn1X509PolicyInformation;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "reqSignature_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certs_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "extensions_", "LLibOrgBouncycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "DEFAULT_VERSION", "I", .constantValue.asInt = LibOrgBouncycastleAsn1DvcsDVCSCertInfo_DEFAULT_VERSION, 0x1a, -1, -1, -1, -1 },
    { "TAG_DV_STATUS", "I", .constantValue.asInt = LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_DV_STATUS, 0x1a, -1, -1, -1, -1 },
    { "TAG_POLICY", "I", .constantValue.asInt = LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_POLICY, 0x1a, -1, -1, -1, -1 },
    { "TAG_REQ_SIGNATURE", "I", .constantValue.asInt = LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_REQ_SIGNATURE, 0x1a, -1, -1, -1, -1 },
    { "TAG_CERTS", "I", .constantValue.asInt = LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_CERTS, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1DvcsDVCSRequestInformation;LLibOrgBouncycastleAsn1X509DigestInfo;LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1DvcsDVCSTime;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "toString", "setVersion", "I", "setDvReqInfo", "LLibOrgBouncycastleAsn1DvcsDVCSRequestInformation;", "setMessageImprint", "LLibOrgBouncycastleAsn1X509DigestInfo;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1DvcsDVCSCertInfo = { "DVCSCertInfo", "lib.org.bouncycastle.asn1.dvcs", ptrTable, methods, fields, 7, 0x1, 19, 15, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1DvcsDVCSCertInfo;
}

@end

void LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_withLibOrgBouncycastleAsn1X509DigestInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1DvcsDVCSTime_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *self, LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *dvReqInfo, LibOrgBouncycastleAsn1X509DigestInfo *messageImprint, LibOrgBouncycastleAsn1ASN1Integer *serialNumber, LibOrgBouncycastleAsn1DvcsDVCSTime *responseTime) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = LibOrgBouncycastleAsn1DvcsDVCSCertInfo_DEFAULT_VERSION;
  self->dvReqInfo_ = dvReqInfo;
  self->messageImprint_ = messageImprint;
  self->serialNumber_ = serialNumber;
  self->responseTime_ = responseTime;
}

LibOrgBouncycastleAsn1DvcsDVCSCertInfo *new_LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_withLibOrgBouncycastleAsn1X509DigestInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1DvcsDVCSTime_(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *dvReqInfo, LibOrgBouncycastleAsn1X509DigestInfo *messageImprint, LibOrgBouncycastleAsn1ASN1Integer *serialNumber, LibOrgBouncycastleAsn1DvcsDVCSTime *responseTime) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_withLibOrgBouncycastleAsn1X509DigestInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1DvcsDVCSTime_, dvReqInfo, messageImprint, serialNumber, responseTime)
}

LibOrgBouncycastleAsn1DvcsDVCSCertInfo *create_LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_withLibOrgBouncycastleAsn1X509DigestInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1DvcsDVCSTime_(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *dvReqInfo, LibOrgBouncycastleAsn1X509DigestInfo *messageImprint, LibOrgBouncycastleAsn1ASN1Integer *serialNumber, LibOrgBouncycastleAsn1DvcsDVCSTime *responseTime) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, initWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_withLibOrgBouncycastleAsn1X509DigestInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1DvcsDVCSTime_, dvReqInfo, messageImprint, serialNumber, responseTime)
}

void LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = LibOrgBouncycastleAsn1DvcsDVCSCertInfo_DEFAULT_VERSION;
  jint i = 0;
  id<LibOrgBouncycastleAsn1ASN1Encodable> x = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:i++];
  @try {
    LibOrgBouncycastleAsn1ASN1Integer *encVersion = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_(x);
    self->version__ = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(encVersion)) getValue])) intValue];
    x = [seq getObjectAtWithInt:i++];
  }
  @catch (JavaLangIllegalArgumentException *e) {
  }
  self->dvReqInfo_ = LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_getInstanceWithId_(x);
  x = [seq getObjectAtWithInt:i++];
  self->messageImprint_ = LibOrgBouncycastleAsn1X509DigestInfo_getInstanceWithId_(x);
  x = [seq getObjectAtWithInt:i++];
  self->serialNumber_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_(x);
  x = [seq getObjectAtWithInt:i++];
  self->responseTime_ = LibOrgBouncycastleAsn1DvcsDVCSTime_getInstanceWithId_(x);
  while (i < [seq size]) {
    x = [seq getObjectAtWithInt:i++];
    if ([x isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
      LibOrgBouncycastleAsn1ASN1TaggedObject *t = LibOrgBouncycastleAsn1ASN1TaggedObject_getInstanceWithId_(x);
      jint tagNo = [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(t)) getTagNo];
      switch (tagNo) {
        case LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_DV_STATUS:
        self->dvStatus_ = LibOrgBouncycastleAsn1CmpPKIStatusInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(t, false);
        break;
        case LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_POLICY:
        self->policy_ = LibOrgBouncycastleAsn1X509PolicyInformation_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(t, false));
        break;
        case LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_REQ_SIGNATURE:
        self->reqSignature_ = LibOrgBouncycastleAsn1ASN1Set_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(t, false);
        break;
        case LibOrgBouncycastleAsn1DvcsDVCSCertInfo_TAG_CERTS:
        self->certs_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(t, false);
        break;
        default:
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Unknown tag encountered: ", tagNo));
      }
      continue;
    }
    @try {
      self->extensions_ = LibOrgBouncycastleAsn1X509Extensions_getInstanceWithId_(x);
    }
    @catch (JavaLangIllegalArgumentException *e) {
    }
  }
}

LibOrgBouncycastleAsn1DvcsDVCSCertInfo *new_LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1DvcsDVCSCertInfo *create_LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DvcsDVCSCertInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1DvcsDVCSCertInfo *LibOrgBouncycastleAsn1DvcsDVCSCertInfo_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1DvcsDVCSCertInfo class]]) {
    return (LibOrgBouncycastleAsn1DvcsDVCSCertInfo *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

LibOrgBouncycastleAsn1DvcsDVCSCertInfo *LibOrgBouncycastleAsn1DvcsDVCSCertInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1DvcsDVCSCertInfo_initialize();
  return LibOrgBouncycastleAsn1DvcsDVCSCertInfo_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

void LibOrgBouncycastleAsn1DvcsDVCSCertInfo_setVersionWithInt_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *self, jint version_) {
  self->version__ = version_;
}

void LibOrgBouncycastleAsn1DvcsDVCSCertInfo_setDvReqInfoWithLibOrgBouncycastleAsn1DvcsDVCSRequestInformation_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *self, LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *dvReqInfo) {
  self->dvReqInfo_ = dvReqInfo;
}

void LibOrgBouncycastleAsn1DvcsDVCSCertInfo_setMessageImprintWithLibOrgBouncycastleAsn1X509DigestInfo_(LibOrgBouncycastleAsn1DvcsDVCSCertInfo *self, LibOrgBouncycastleAsn1X509DigestInfo *messageImprint) {
  self->messageImprint_ = messageImprint;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1DvcsDVCSCertInfo)
