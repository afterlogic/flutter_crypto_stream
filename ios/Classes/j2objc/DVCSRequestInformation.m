//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/dvcs/DVCSRequestInformation.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1GeneralizedTime.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "DVCSRequestInformation.h"
#include "DVCSTime.h"
#include "Extensions.h"
#include "GeneralNames.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PolicyInformation.h"
#include "ServiceType.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/StringBuffer.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1DvcsDVCSRequestInformation () {
 @public
  jint version__;
  LibOrgBouncycastleAsn1DvcsServiceType *service_;
  JavaMathBigInteger *nonce_;
  LibOrgBouncycastleAsn1DvcsDVCSTime *requestTime_;
  LibOrgBouncycastleAsn1X509GeneralNames *requester_;
  LibOrgBouncycastleAsn1X509PolicyInformation *requestPolicy_;
  LibOrgBouncycastleAsn1X509GeneralNames *dvcs_;
  LibOrgBouncycastleAsn1X509GeneralNames *dataLocations_;
  LibOrgBouncycastleAsn1X509Extensions *extensions_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, service_, LibOrgBouncycastleAsn1DvcsServiceType *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, nonce_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, requestTime_, LibOrgBouncycastleAsn1DvcsDVCSTime *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, requester_, LibOrgBouncycastleAsn1X509GeneralNames *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, requestPolicy_, LibOrgBouncycastleAsn1X509PolicyInformation *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, dvcs_, LibOrgBouncycastleAsn1X509GeneralNames *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, dataLocations_, LibOrgBouncycastleAsn1X509GeneralNames *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, extensions_, LibOrgBouncycastleAsn1X509Extensions *)

inline jint LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_get_DEFAULT_VERSION(void);
#define LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_DEFAULT_VERSION 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, DEFAULT_VERSION, jint)

inline jint LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_get_TAG_REQUESTER(void);
#define LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_REQUESTER 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, TAG_REQUESTER, jint)

inline jint LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_get_TAG_REQUEST_POLICY(void);
#define LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_REQUEST_POLICY 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, TAG_REQUEST_POLICY, jint)

inline jint LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_get_TAG_DVCS(void);
#define LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_DVCS 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, TAG_DVCS, jint)

inline jint LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_get_TAG_DATA_LOCATIONS(void);
#define LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_DATA_LOCATIONS 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, TAG_DATA_LOCATIONS, jint)

inline jint LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_get_TAG_EXTENSIONS(void);
#define LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_EXTENSIONS 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, TAG_EXTENSIONS, jint)

__attribute__((unused)) static void LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *new_LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *create_LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1DvcsDVCSRequestInformation

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                                withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  if (version__ != LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_DEFAULT_VERSION) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(version__)];
  }
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:service_];
  if (nonce_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(nonce_)];
  }
  if (requestTime_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:requestTime_];
  }
  IOSIntArray *tags = [IOSIntArray newArrayWithInts:(jint[]){ LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_REQUESTER, LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_REQUEST_POLICY, LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_DVCS, LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_DATA_LOCATIONS, LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_EXTENSIONS } count:5];
  IOSObjectArray *taggedObjects = [IOSObjectArray newArrayWithObjects:(id[]){ requester_, requestPolicy_, dvcs_, dataLocations_, extensions_ } count:5 type:LibOrgBouncycastleAsn1ASN1Encodable_class_()];
  for (jint i = 0; i < tags->size_; i++) {
    jint tag = IOSIntArray_Get(tags, i);
    id<LibOrgBouncycastleAsn1ASN1Encodable> taggedObject = IOSObjectArray_Get(taggedObjects, i);
    if (taggedObject != nil) {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, tag, taggedObject)];
    }
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

- (NSString *)description {
  JavaLangStringBuffer *s = new_JavaLangStringBuffer_init();
  (void) [s appendWithNSString:@"DVCSRequestInformation {\n"];
  if (version__ != LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_DEFAULT_VERSION) {
    (void) [s appendWithNSString:JreStrcat("$IC", @"version: ", version__, 0x000a)];
  }
  (void) [s appendWithNSString:JreStrcat("$@C", @"service: ", service_, 0x000a)];
  if (nonce_ != nil) {
    (void) [s appendWithNSString:JreStrcat("$@C", @"nonce: ", nonce_, 0x000a)];
  }
  if (requestTime_ != nil) {
    (void) [s appendWithNSString:JreStrcat("$@C", @"requestTime: ", requestTime_, 0x000a)];
  }
  if (requester_ != nil) {
    (void) [s appendWithNSString:JreStrcat("$@C", @"requester: ", requester_, 0x000a)];
  }
  if (requestPolicy_ != nil) {
    (void) [s appendWithNSString:JreStrcat("$@C", @"requestPolicy: ", requestPolicy_, 0x000a)];
  }
  if (dvcs_ != nil) {
    (void) [s appendWithNSString:JreStrcat("$@C", @"dvcs: ", dvcs_, 0x000a)];
  }
  if (dataLocations_ != nil) {
    (void) [s appendWithNSString:JreStrcat("$@C", @"dataLocations: ", dataLocations_, 0x000a)];
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

- (LibOrgBouncycastleAsn1DvcsServiceType *)getService {
  return service_;
}

- (JavaMathBigInteger *)getNonce {
  return nonce_;
}

- (LibOrgBouncycastleAsn1DvcsDVCSTime *)getRequestTime {
  return requestTime_;
}

- (LibOrgBouncycastleAsn1X509GeneralNames *)getRequester {
  return requester_;
}

- (LibOrgBouncycastleAsn1X509PolicyInformation *)getRequestPolicy {
  return requestPolicy_;
}

- (LibOrgBouncycastleAsn1X509GeneralNames *)getDVCS {
  return dvcs_;
}

- (LibOrgBouncycastleAsn1X509GeneralNames *)getDataLocations {
  return dataLocations_;
}

- (LibOrgBouncycastleAsn1X509Extensions *)getExtensions {
  return extensions_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DvcsDVCSRequestInformation;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DvcsDVCSRequestInformation;", 0x9, 1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 4, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DvcsServiceType;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DvcsDVCSTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509GeneralNames;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509PolicyInformation;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509GeneralNames;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509GeneralNames;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(toASN1Primitive);
  methods[4].selector = @selector(description);
  methods[5].selector = @selector(getVersion);
  methods[6].selector = @selector(getService);
  methods[7].selector = @selector(getNonce);
  methods[8].selector = @selector(getRequestTime);
  methods[9].selector = @selector(getRequester);
  methods[10].selector = @selector(getRequestPolicy);
  methods[11].selector = @selector(getDVCS);
  methods[12].selector = @selector(getDataLocations);
  methods[13].selector = @selector(getExtensions);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "I", .constantValue.asLong = 0, 0x2, 5, -1, -1, -1 },
    { "service_", "LLibOrgBouncycastleAsn1DvcsServiceType;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "nonce_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "requestTime_", "LLibOrgBouncycastleAsn1DvcsDVCSTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "requester_", "LLibOrgBouncycastleAsn1X509GeneralNames;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "requestPolicy_", "LLibOrgBouncycastleAsn1X509PolicyInformation;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dvcs_", "LLibOrgBouncycastleAsn1X509GeneralNames;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dataLocations_", "LLibOrgBouncycastleAsn1X509GeneralNames;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "extensions_", "LLibOrgBouncycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "DEFAULT_VERSION", "I", .constantValue.asInt = LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_DEFAULT_VERSION, 0x1a, -1, -1, -1, -1 },
    { "TAG_REQUESTER", "I", .constantValue.asInt = LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_REQUESTER, 0x1a, -1, -1, -1, -1 },
    { "TAG_REQUEST_POLICY", "I", .constantValue.asInt = LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_REQUEST_POLICY, 0x1a, -1, -1, -1, -1 },
    { "TAG_DVCS", "I", .constantValue.asInt = LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_DVCS, 0x1a, -1, -1, -1, -1 },
    { "TAG_DATA_LOCATIONS", "I", .constantValue.asInt = LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_DATA_LOCATIONS, 0x1a, -1, -1, -1, -1 },
    { "TAG_EXTENSIONS", "I", .constantValue.asInt = LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_EXTENSIONS, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "toString", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1DvcsDVCSRequestInformation = { "DVCSRequestInformation", "lib.org.bouncycastle.asn1.dvcs", ptrTable, methods, fields, 7, 0x1, 14, 15, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1DvcsDVCSRequestInformation;
}

@end

void LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_DEFAULT_VERSION;
  jint i = 0;
  if ([[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0] isKindOfClass:[LibOrgBouncycastleAsn1ASN1Integer class]]) {
    LibOrgBouncycastleAsn1ASN1Integer *encVersion = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:i++]);
    self->version__ = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(encVersion)) getValue])) intValue];
  }
  else {
    self->version__ = 1;
  }
  self->service_ = LibOrgBouncycastleAsn1DvcsServiceType_getInstanceWithId_([seq getObjectAtWithInt:i++]);
  while (i < [seq size]) {
    id<LibOrgBouncycastleAsn1ASN1Encodable> x = [seq getObjectAtWithInt:i];
    if ([x isKindOfClass:[LibOrgBouncycastleAsn1ASN1Integer class]]) {
      self->nonce_ = [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_(x))) getValue];
    }
    else if ([x isKindOfClass:[LibOrgBouncycastleAsn1ASN1GeneralizedTime class]]) {
      self->requestTime_ = LibOrgBouncycastleAsn1DvcsDVCSTime_getInstanceWithId_(x);
    }
    else if ([x isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
      LibOrgBouncycastleAsn1ASN1TaggedObject *t = LibOrgBouncycastleAsn1ASN1TaggedObject_getInstanceWithId_(x);
      jint tagNo = [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(t)) getTagNo];
      switch (tagNo) {
        case LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_REQUESTER:
        self->requester_ = LibOrgBouncycastleAsn1X509GeneralNames_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(t, false);
        break;
        case LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_REQUEST_POLICY:
        self->requestPolicy_ = LibOrgBouncycastleAsn1X509PolicyInformation_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(t, false));
        break;
        case LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_DVCS:
        self->dvcs_ = LibOrgBouncycastleAsn1X509GeneralNames_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(t, false);
        break;
        case LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_DATA_LOCATIONS:
        self->dataLocations_ = LibOrgBouncycastleAsn1X509GeneralNames_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(t, false);
        break;
        case LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_TAG_EXTENSIONS:
        self->extensions_ = LibOrgBouncycastleAsn1X509Extensions_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(t, false);
        break;
        default:
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"unknown tag number encountered: ", tagNo));
      }
    }
    else {
      self->requestTime_ = LibOrgBouncycastleAsn1DvcsDVCSTime_getInstanceWithId_(x);
    }
    i++;
  }
}

LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *new_LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *create_LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1DvcsDVCSRequestInformation class]]) {
    return (LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

LibOrgBouncycastleAsn1DvcsDVCSRequestInformation *LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_initialize();
  return LibOrgBouncycastleAsn1DvcsDVCSRequestInformation_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1DvcsDVCSRequestInformation)
