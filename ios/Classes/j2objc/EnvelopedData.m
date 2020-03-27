//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/EnvelopedData.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1Set.h"
#include "ASN1TaggedObject.h"
#include "Attributes.h"
#include "BERSequence.h"
#include "DERTaggedObject.h"
#include "EncryptedContentInfo.h"
#include "EnvelopedData.h"
#include "J2ObjC_source.h"
#include "OriginatorInfo.h"
#include "RecipientInfo.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1CmsEnvelopedData () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *version__;
  LibOrgBouncycastleAsn1CmsOriginatorInfo *originatorInfo_;
  LibOrgBouncycastleAsn1ASN1Set *recipientInfos_;
  LibOrgBouncycastleAsn1CmsEncryptedContentInfo *encryptedContentInfo_;
  LibOrgBouncycastleAsn1ASN1Set *unprotectedAttrs_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsEnvelopedData, version__, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsEnvelopedData, originatorInfo_, LibOrgBouncycastleAsn1CmsOriginatorInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsEnvelopedData, recipientInfos_, LibOrgBouncycastleAsn1ASN1Set *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsEnvelopedData, encryptedContentInfo_, LibOrgBouncycastleAsn1CmsEncryptedContentInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmsEnvelopedData, unprotectedAttrs_, LibOrgBouncycastleAsn1ASN1Set *)

@implementation LibOrgBouncycastleAsn1CmsEnvelopedData

- (instancetype)initWithLibOrgBouncycastleAsn1CmsOriginatorInfo:(LibOrgBouncycastleAsn1CmsOriginatorInfo *)originatorInfo
                              withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)recipientInfos
              withLibOrgBouncycastleAsn1CmsEncryptedContentInfo:(LibOrgBouncycastleAsn1CmsEncryptedContentInfo *)encryptedContentInfo
                              withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)unprotectedAttrs {
  LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1ASN1Set_(self, originatorInfo, recipientInfos, encryptedContentInfo, unprotectedAttrs);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmsOriginatorInfo:(LibOrgBouncycastleAsn1CmsOriginatorInfo *)originatorInfo
                              withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)recipientInfos
              withLibOrgBouncycastleAsn1CmsEncryptedContentInfo:(LibOrgBouncycastleAsn1CmsEncryptedContentInfo *)encryptedContentInfo
                        withLibOrgBouncycastleAsn1CmsAttributes:(LibOrgBouncycastleAsn1CmsAttributes *)unprotectedAttrs {
  LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1CmsAttributes_(self, originatorInfo, recipientInfos, encryptedContentInfo, unprotectedAttrs);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CmsEnvelopedData *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CmsEnvelopedData_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1CmsEnvelopedData *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CmsEnvelopedData_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (LibOrgBouncycastleAsn1CmsOriginatorInfo *)getOriginatorInfo {
  return originatorInfo_;
}

- (LibOrgBouncycastleAsn1ASN1Set *)getRecipientInfos {
  return recipientInfos_;
}

- (LibOrgBouncycastleAsn1CmsEncryptedContentInfo *)getEncryptedContentInfo {
  return encryptedContentInfo_;
}

- (LibOrgBouncycastleAsn1ASN1Set *)getUnprotectedAttrs {
  return unprotectedAttrs_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:version__];
  if (originatorInfo_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 0, originatorInfo_)];
  }
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:recipientInfos_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:encryptedContentInfo_];
  if (unprotectedAttrs_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 1, unprotectedAttrs_)];
  }
  return new_LibOrgBouncycastleAsn1BERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (jint)calculateVersionWithLibOrgBouncycastleAsn1CmsOriginatorInfo:(LibOrgBouncycastleAsn1CmsOriginatorInfo *)originatorInfo
                                  withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)recipientInfos
                                  withLibOrgBouncycastleAsn1ASN1Set:(LibOrgBouncycastleAsn1ASN1Set *)unprotectedAttrs {
  return LibOrgBouncycastleAsn1CmsEnvelopedData_calculateVersionWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(originatorInfo, recipientInfos, unprotectedAttrs);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsEnvelopedData;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsEnvelopedData;", 0x9, 3, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsOriginatorInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmsEncryptedContentInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 6, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1CmsOriginatorInfo:withLibOrgBouncycastleAsn1ASN1Set:withLibOrgBouncycastleAsn1CmsEncryptedContentInfo:withLibOrgBouncycastleAsn1ASN1Set:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1CmsOriginatorInfo:withLibOrgBouncycastleAsn1ASN1Set:withLibOrgBouncycastleAsn1CmsEncryptedContentInfo:withLibOrgBouncycastleAsn1CmsAttributes:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[4].selector = @selector(getInstanceWithId:);
  methods[5].selector = @selector(getVersion);
  methods[6].selector = @selector(getOriginatorInfo);
  methods[7].selector = @selector(getRecipientInfos);
  methods[8].selector = @selector(getEncryptedContentInfo);
  methods[9].selector = @selector(getUnprotectedAttrs);
  methods[10].selector = @selector(toASN1Primitive);
  methods[11].selector = @selector(calculateVersionWithLibOrgBouncycastleAsn1CmsOriginatorInfo:withLibOrgBouncycastleAsn1ASN1Set:withLibOrgBouncycastleAsn1ASN1Set:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, 8, -1, -1, -1 },
    { "originatorInfo_", "LLibOrgBouncycastleAsn1CmsOriginatorInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "recipientInfos_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encryptedContentInfo_", "LLibOrgBouncycastleAsn1CmsEncryptedContentInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "unprotectedAttrs_", "LLibOrgBouncycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1CmsOriginatorInfo;LLibOrgBouncycastleAsn1ASN1Set;LLibOrgBouncycastleAsn1CmsEncryptedContentInfo;LLibOrgBouncycastleAsn1ASN1Set;", "LLibOrgBouncycastleAsn1CmsOriginatorInfo;LLibOrgBouncycastleAsn1ASN1Set;LLibOrgBouncycastleAsn1CmsEncryptedContentInfo;LLibOrgBouncycastleAsn1CmsAttributes;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "calculateVersion", "LLibOrgBouncycastleAsn1CmsOriginatorInfo;LLibOrgBouncycastleAsn1ASN1Set;LLibOrgBouncycastleAsn1ASN1Set;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmsEnvelopedData = { "EnvelopedData", "lib.org.bouncycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 12, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmsEnvelopedData;
}

@end

void LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmsEnvelopedData *self, LibOrgBouncycastleAsn1CmsOriginatorInfo *originatorInfo, LibOrgBouncycastleAsn1ASN1Set *recipientInfos, LibOrgBouncycastleAsn1CmsEncryptedContentInfo *encryptedContentInfo, LibOrgBouncycastleAsn1ASN1Set *unprotectedAttrs) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(LibOrgBouncycastleAsn1CmsEnvelopedData_calculateVersionWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(originatorInfo, recipientInfos, unprotectedAttrs));
  self->originatorInfo_ = originatorInfo;
  self->recipientInfos_ = recipientInfos;
  self->encryptedContentInfo_ = encryptedContentInfo;
  self->unprotectedAttrs_ = unprotectedAttrs;
}

LibOrgBouncycastleAsn1CmsEnvelopedData *new_LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmsOriginatorInfo *originatorInfo, LibOrgBouncycastleAsn1ASN1Set *recipientInfos, LibOrgBouncycastleAsn1CmsEncryptedContentInfo *encryptedContentInfo, LibOrgBouncycastleAsn1ASN1Set *unprotectedAttrs) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsEnvelopedData, initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1ASN1Set_, originatorInfo, recipientInfos, encryptedContentInfo, unprotectedAttrs)
}

LibOrgBouncycastleAsn1CmsEnvelopedData *create_LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmsOriginatorInfo *originatorInfo, LibOrgBouncycastleAsn1ASN1Set *recipientInfos, LibOrgBouncycastleAsn1CmsEncryptedContentInfo *encryptedContentInfo, LibOrgBouncycastleAsn1ASN1Set *unprotectedAttrs) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsEnvelopedData, initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1ASN1Set_, originatorInfo, recipientInfos, encryptedContentInfo, unprotectedAttrs)
}

void LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1CmsAttributes_(LibOrgBouncycastleAsn1CmsEnvelopedData *self, LibOrgBouncycastleAsn1CmsOriginatorInfo *originatorInfo, LibOrgBouncycastleAsn1ASN1Set *recipientInfos, LibOrgBouncycastleAsn1CmsEncryptedContentInfo *encryptedContentInfo, LibOrgBouncycastleAsn1CmsAttributes *unprotectedAttrs) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(LibOrgBouncycastleAsn1CmsEnvelopedData_calculateVersionWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(originatorInfo, recipientInfos, LibOrgBouncycastleAsn1ASN1Set_getInstanceWithId_(unprotectedAttrs)));
  self->originatorInfo_ = originatorInfo;
  self->recipientInfos_ = recipientInfos;
  self->encryptedContentInfo_ = encryptedContentInfo;
  self->unprotectedAttrs_ = LibOrgBouncycastleAsn1ASN1Set_getInstanceWithId_(unprotectedAttrs);
}

LibOrgBouncycastleAsn1CmsEnvelopedData *new_LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1CmsAttributes_(LibOrgBouncycastleAsn1CmsOriginatorInfo *originatorInfo, LibOrgBouncycastleAsn1ASN1Set *recipientInfos, LibOrgBouncycastleAsn1CmsEncryptedContentInfo *encryptedContentInfo, LibOrgBouncycastleAsn1CmsAttributes *unprotectedAttrs) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsEnvelopedData, initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1CmsAttributes_, originatorInfo, recipientInfos, encryptedContentInfo, unprotectedAttrs)
}

LibOrgBouncycastleAsn1CmsEnvelopedData *create_LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1CmsAttributes_(LibOrgBouncycastleAsn1CmsOriginatorInfo *originatorInfo, LibOrgBouncycastleAsn1ASN1Set *recipientInfos, LibOrgBouncycastleAsn1CmsEncryptedContentInfo *encryptedContentInfo, LibOrgBouncycastleAsn1CmsAttributes *unprotectedAttrs) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsEnvelopedData, initWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1CmsEncryptedContentInfo_withLibOrgBouncycastleAsn1CmsAttributes_, originatorInfo, recipientInfos, encryptedContentInfo, unprotectedAttrs)
}

void LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsEnvelopedData *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  jint index = 0;
  self->version__ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:index++], [LibOrgBouncycastleAsn1ASN1Integer class]);
  id tmp = [seq getObjectAtWithInt:index++];
  if ([tmp isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
    self->originatorInfo_ = LibOrgBouncycastleAsn1CmsOriginatorInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) tmp, false);
    tmp = [seq getObjectAtWithInt:index++];
  }
  self->recipientInfos_ = LibOrgBouncycastleAsn1ASN1Set_getInstanceWithId_(tmp);
  self->encryptedContentInfo_ = LibOrgBouncycastleAsn1CmsEncryptedContentInfo_getInstanceWithId_([seq getObjectAtWithInt:index++]);
  if ([seq size] > index) {
    self->unprotectedAttrs_ = LibOrgBouncycastleAsn1ASN1Set_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_((LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:index], [LibOrgBouncycastleAsn1ASN1TaggedObject class]), false);
  }
}

LibOrgBouncycastleAsn1CmsEnvelopedData *new_LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmsEnvelopedData, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsEnvelopedData *create_LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmsEnvelopedData, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmsEnvelopedData *LibOrgBouncycastleAsn1CmsEnvelopedData_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CmsEnvelopedData_initialize();
  return LibOrgBouncycastleAsn1CmsEnvelopedData_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1CmsEnvelopedData *LibOrgBouncycastleAsn1CmsEnvelopedData_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CmsEnvelopedData_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CmsEnvelopedData class]]) {
    return (LibOrgBouncycastleAsn1CmsEnvelopedData *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CmsEnvelopedData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

jint LibOrgBouncycastleAsn1CmsEnvelopedData_calculateVersionWithLibOrgBouncycastleAsn1CmsOriginatorInfo_withLibOrgBouncycastleAsn1ASN1Set_withLibOrgBouncycastleAsn1ASN1Set_(LibOrgBouncycastleAsn1CmsOriginatorInfo *originatorInfo, LibOrgBouncycastleAsn1ASN1Set *recipientInfos, LibOrgBouncycastleAsn1ASN1Set *unprotectedAttrs) {
  LibOrgBouncycastleAsn1CmsEnvelopedData_initialize();
  jint version_;
  if (originatorInfo != nil || unprotectedAttrs != nil) {
    version_ = 2;
  }
  else {
    version_ = 0;
    id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Set *) nil_chk(recipientInfos)) getObjects];
    while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
      LibOrgBouncycastleAsn1CmsRecipientInfo *ri = LibOrgBouncycastleAsn1CmsRecipientInfo_getInstanceWithId_([e nextElement]);
      if ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk([((LibOrgBouncycastleAsn1CmsRecipientInfo *) nil_chk(ri)) getVersion])) getValue])) intValue] != version_) {
        version_ = 2;
        break;
      }
    }
  }
  return version_;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmsEnvelopedData)