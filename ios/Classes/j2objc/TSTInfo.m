//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/tsp/TSTInfo.java
//

#include "ASN1Boolean.h"
#include "ASN1EncodableVector.h"
#include "ASN1GeneralizedTime.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "Accuracy.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "Extensions.h"
#include "GeneralName.h"
#include "J2ObjC_source.h"
#include "MessageImprint.h"
#include "TSTInfo.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1TspTSTInfo () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *version__;
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *tsaPolicyId_;
  LibOrgBouncycastleAsn1TspMessageImprint *messageImprint_;
  LibOrgBouncycastleAsn1ASN1Integer *serialNumber_;
  LibOrgBouncycastleAsn1ASN1GeneralizedTime *genTime_;
  LibOrgBouncycastleAsn1TspAccuracy *accuracy_;
  LibOrgBouncycastleAsn1ASN1Boolean *ordering_;
  LibOrgBouncycastleAsn1ASN1Integer *nonce_;
  LibOrgBouncycastleAsn1X509GeneralName *tsa_;
  LibOrgBouncycastleAsn1X509Extensions *extensions_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTSTInfo, version__, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTSTInfo, tsaPolicyId_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTSTInfo, messageImprint_, LibOrgBouncycastleAsn1TspMessageImprint *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTSTInfo, serialNumber_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTSTInfo, genTime_, LibOrgBouncycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTSTInfo, accuracy_, LibOrgBouncycastleAsn1TspAccuracy *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTSTInfo, ordering_, LibOrgBouncycastleAsn1ASN1Boolean *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTSTInfo, nonce_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTSTInfo, tsa_, LibOrgBouncycastleAsn1X509GeneralName *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTSTInfo, extensions_, LibOrgBouncycastleAsn1X509Extensions *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1TspTSTInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1TspTSTInfo *new_LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1TspTSTInfo *create_LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1TspTSTInfo

+ (LibOrgBouncycastleAsn1TspTSTInfo *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1TspTSTInfo_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)tsaPolicyId
                       withLibOrgBouncycastleAsn1TspMessageImprint:(LibOrgBouncycastleAsn1TspMessageImprint *)messageImprint
                             withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)serialNumber
                     withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)genTime
                             withLibOrgBouncycastleAsn1TspAccuracy:(LibOrgBouncycastleAsn1TspAccuracy *)accuracy
                             withLibOrgBouncycastleAsn1ASN1Boolean:(LibOrgBouncycastleAsn1ASN1Boolean *)ordering
                             withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)nonce
                         withLibOrgBouncycastleAsn1X509GeneralName:(LibOrgBouncycastleAsn1X509GeneralName *)tsa
                          withLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions {
  LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1TspAccuracy_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509Extensions_(self, tsaPolicyId, messageImprint, serialNumber, genTime, accuracy, ordering, nonce, tsa, extensions);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (LibOrgBouncycastleAsn1TspMessageImprint *)getMessageImprint {
  return messageImprint_;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getPolicy {
  return tsaPolicyId_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getSerialNumber {
  return serialNumber_;
}

- (LibOrgBouncycastleAsn1TspAccuracy *)getAccuracy {
  return accuracy_;
}

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getGenTime {
  return genTime_;
}

- (LibOrgBouncycastleAsn1ASN1Boolean *)getOrdering {
  return ordering_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getNonce {
  return nonce_;
}

- (LibOrgBouncycastleAsn1X509GeneralName *)getTsa {
  return tsa_;
}

- (LibOrgBouncycastleAsn1X509Extensions *)getExtensions {
  return extensions_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *seq = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [seq addWithLibOrgBouncycastleAsn1ASN1Encodable:version__];
  [seq addWithLibOrgBouncycastleAsn1ASN1Encodable:tsaPolicyId_];
  [seq addWithLibOrgBouncycastleAsn1ASN1Encodable:messageImprint_];
  [seq addWithLibOrgBouncycastleAsn1ASN1Encodable:serialNumber_];
  [seq addWithLibOrgBouncycastleAsn1ASN1Encodable:genTime_];
  if (accuracy_ != nil) {
    [seq addWithLibOrgBouncycastleAsn1ASN1Encodable:accuracy_];
  }
  if (ordering_ != nil && [ordering_ isTrue]) {
    [seq addWithLibOrgBouncycastleAsn1ASN1Encodable:ordering_];
  }
  if (nonce_ != nil) {
    [seq addWithLibOrgBouncycastleAsn1ASN1Encodable:nonce_];
  }
  if (tsa_ != nil) {
    [seq addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 0, tsa_)];
  }
  if (extensions_ != nil) {
    [seq addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 1, extensions_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(seq);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1TspTSTInfo;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1TspMessageImprint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1TspAccuracy;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Boolean;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509GeneralName;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1TspMessageImprint:withLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1ASN1GeneralizedTime:withLibOrgBouncycastleAsn1TspAccuracy:withLibOrgBouncycastleAsn1ASN1Boolean:withLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1X509GeneralName:withLibOrgBouncycastleAsn1X509Extensions:);
  methods[3].selector = @selector(getVersion);
  methods[4].selector = @selector(getMessageImprint);
  methods[5].selector = @selector(getPolicy);
  methods[6].selector = @selector(getSerialNumber);
  methods[7].selector = @selector(getAccuracy);
  methods[8].selector = @selector(getGenTime);
  methods[9].selector = @selector(getOrdering);
  methods[10].selector = @selector(getNonce);
  methods[11].selector = @selector(getTsa);
  methods[12].selector = @selector(getExtensions);
  methods[13].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, 4, -1, -1, -1 },
    { "tsaPolicyId_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "messageImprint_", "LLibOrgBouncycastleAsn1TspMessageImprint;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "serialNumber_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "genTime_", "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "accuracy_", "LLibOrgBouncycastleAsn1TspAccuracy;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ordering_", "LLibOrgBouncycastleAsn1ASN1Boolean;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "nonce_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "tsa_", "LLibOrgBouncycastleAsn1X509GeneralName;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "extensions_", "LLibOrgBouncycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1TspMessageImprint;LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1ASN1GeneralizedTime;LLibOrgBouncycastleAsn1TspAccuracy;LLibOrgBouncycastleAsn1ASN1Boolean;LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1X509GeneralName;LLibOrgBouncycastleAsn1X509Extensions;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1TspTSTInfo = { "TSTInfo", "lib.org.bouncycastle.asn1.tsp", ptrTable, methods, fields, 7, 0x1, 14, 10, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1TspTSTInfo;
}

@end

LibOrgBouncycastleAsn1TspTSTInfo *LibOrgBouncycastleAsn1TspTSTInfo_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1TspTSTInfo_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1TspTSTInfo class]]) {
    return (LibOrgBouncycastleAsn1TspTSTInfo *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1TspTSTInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->version__ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement]);
  self->tsaPolicyId_ = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([e nextElement]);
  self->messageImprint_ = LibOrgBouncycastleAsn1TspMessageImprint_getInstanceWithId_([e nextElement]);
  self->serialNumber_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([e nextElement]);
  self->genTime_ = LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_([e nextElement]);
  self->ordering_ = LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithBoolean_(false);
  while ([e hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1Object *o = (LibOrgBouncycastleAsn1ASN1Object *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1Object class]);
    if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
      LibOrgBouncycastleAsn1ASN1TaggedObject *tagged = (LibOrgBouncycastleAsn1ASN1TaggedObject *) o;
      switch ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(tagged)) getTagNo]) {
        case 0:
        self->tsa_ = LibOrgBouncycastleAsn1X509GeneralName_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tagged, true);
        break;
        case 1:
        self->extensions_ = LibOrgBouncycastleAsn1X509Extensions_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tagged, false);
        break;
        default:
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Unknown tag value ", [tagged getTagNo]));
      }
    }
    else if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]] || [o isKindOfClass:[LibOrgBouncycastleAsn1TspAccuracy class]]) {
      self->accuracy_ = LibOrgBouncycastleAsn1TspAccuracy_getInstanceWithId_(o);
    }
    else if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Boolean class]]) {
      self->ordering_ = LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithId_(o);
    }
    else if ([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1Integer class]]) {
      self->nonce_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_(o);
    }
  }
}

LibOrgBouncycastleAsn1TspTSTInfo *new_LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1TspTSTInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1TspTSTInfo *create_LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1TspTSTInfo, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1TspAccuracy_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1TspTSTInfo *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *tsaPolicyId, LibOrgBouncycastleAsn1TspMessageImprint *messageImprint, LibOrgBouncycastleAsn1ASN1Integer *serialNumber, LibOrgBouncycastleAsn1ASN1GeneralizedTime *genTime, LibOrgBouncycastleAsn1TspAccuracy *accuracy, LibOrgBouncycastleAsn1ASN1Boolean *ordering, LibOrgBouncycastleAsn1ASN1Integer *nonce, LibOrgBouncycastleAsn1X509GeneralName *tsa, LibOrgBouncycastleAsn1X509Extensions *extensions) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(1);
  self->tsaPolicyId_ = tsaPolicyId;
  self->messageImprint_ = messageImprint;
  self->serialNumber_ = serialNumber;
  self->genTime_ = genTime;
  self->accuracy_ = accuracy;
  self->ordering_ = ordering;
  self->nonce_ = nonce;
  self->tsa_ = tsa;
  self->extensions_ = extensions;
}

LibOrgBouncycastleAsn1TspTSTInfo *new_LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1TspAccuracy_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *tsaPolicyId, LibOrgBouncycastleAsn1TspMessageImprint *messageImprint, LibOrgBouncycastleAsn1ASN1Integer *serialNumber, LibOrgBouncycastleAsn1ASN1GeneralizedTime *genTime, LibOrgBouncycastleAsn1TspAccuracy *accuracy, LibOrgBouncycastleAsn1ASN1Boolean *ordering, LibOrgBouncycastleAsn1ASN1Integer *nonce, LibOrgBouncycastleAsn1X509GeneralName *tsa, LibOrgBouncycastleAsn1X509Extensions *extensions) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1TspTSTInfo, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1TspAccuracy_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509Extensions_, tsaPolicyId, messageImprint, serialNumber, genTime, accuracy, ordering, nonce, tsa, extensions)
}

LibOrgBouncycastleAsn1TspTSTInfo *create_LibOrgBouncycastleAsn1TspTSTInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1TspAccuracy_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *tsaPolicyId, LibOrgBouncycastleAsn1TspMessageImprint *messageImprint, LibOrgBouncycastleAsn1ASN1Integer *serialNumber, LibOrgBouncycastleAsn1ASN1GeneralizedTime *genTime, LibOrgBouncycastleAsn1TspAccuracy *accuracy, LibOrgBouncycastleAsn1ASN1Boolean *ordering, LibOrgBouncycastleAsn1ASN1Integer *nonce, LibOrgBouncycastleAsn1X509GeneralName *tsa, LibOrgBouncycastleAsn1X509Extensions *extensions) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1TspTSTInfo, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1TspAccuracy_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X509GeneralName_withLibOrgBouncycastleAsn1X509Extensions_, tsaPolicyId, messageImprint, serialNumber, genTime, accuracy, ordering, nonce, tsa, extensions)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1TspTSTInfo)
