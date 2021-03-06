//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/tsp/TimeStampReq.java
//

#include "ASN1Boolean.h"
#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "Extensions.h"
#include "J2ObjC_source.h"
#include "MessageImprint.h"
#include "TimeStampReq.h"

@interface LibOrgBouncycastleAsn1TspTimeStampReq ()

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1TspTimeStampReq *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1TspTimeStampReq *new_LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1TspTimeStampReq *create_LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1TspTimeStampReq

+ (LibOrgBouncycastleAsn1TspTimeStampReq *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1TspTimeStampReq_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1TspMessageImprint:(LibOrgBouncycastleAsn1TspMessageImprint *)messageImprint
                 withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)tsaPolicy
                          withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)nonce
                          withLibOrgBouncycastleAsn1ASN1Boolean:(LibOrgBouncycastleAsn1ASN1Boolean *)certReq
                       withLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions {
  LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1X509Extensions_(self, messageImprint, tsaPolicy, nonce, certReq, extensions);
  return self;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (LibOrgBouncycastleAsn1TspMessageImprint *)getMessageImprint {
  return messageImprint_;
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getReqPolicy {
  return tsaPolicy_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getNonce {
  return nonce_;
}

- (LibOrgBouncycastleAsn1ASN1Boolean *)getCertReq {
  return certReq_;
}

- (LibOrgBouncycastleAsn1X509Extensions *)getExtensions {
  return extensions_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:version__];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:messageImprint_];
  if (tsaPolicy_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:tsaPolicy_];
  }
  if (nonce_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:nonce_];
  }
  if (certReq_ != nil && [certReq_ isTrue]) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certReq_];
  }
  if (extensions_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 0, extensions_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1TspTimeStampReq;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1TspMessageImprint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Boolean;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1TspMessageImprint:withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1ASN1Boolean:withLibOrgBouncycastleAsn1X509Extensions:);
  methods[3].selector = @selector(getVersion);
  methods[4].selector = @selector(getMessageImprint);
  methods[5].selector = @selector(getReqPolicy);
  methods[6].selector = @selector(getNonce);
  methods[7].selector = @selector(getCertReq);
  methods[8].selector = @selector(getExtensions);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, 4, -1, -1, -1 },
    { "messageImprint_", "LLibOrgBouncycastleAsn1TspMessageImprint;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "tsaPolicy_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "nonce_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "certReq_", "LLibOrgBouncycastleAsn1ASN1Boolean;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "extensions_", "LLibOrgBouncycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1TspMessageImprint;LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1ASN1Boolean;LLibOrgBouncycastleAsn1X509Extensions;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1TspTimeStampReq = { "TimeStampReq", "lib.org.bouncycastle.asn1.tsp", ptrTable, methods, fields, 7, 0x1, 10, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1TspTimeStampReq;
}

@end

LibOrgBouncycastleAsn1TspTimeStampReq *LibOrgBouncycastleAsn1TspTimeStampReq_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1TspTimeStampReq_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1TspTimeStampReq class]]) {
    return (LibOrgBouncycastleAsn1TspTimeStampReq *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1TspTimeStampReq *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  jint nbObjects = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size];
  jint seqStart = 0;
  self->version__ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:seqStart]);
  seqStart++;
  self->messageImprint_ = LibOrgBouncycastleAsn1TspMessageImprint_getInstanceWithId_([seq getObjectAtWithInt:seqStart]);
  seqStart++;
  for (jint opt = seqStart; opt < nbObjects; opt++) {
    if ([[seq getObjectAtWithInt:opt] isKindOfClass:[LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]]) {
      self->tsaPolicy_ = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([seq getObjectAtWithInt:opt]);
    }
    else if ([[seq getObjectAtWithInt:opt] isKindOfClass:[LibOrgBouncycastleAsn1ASN1Integer class]]) {
      self->nonce_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:opt]);
    }
    else if ([[seq getObjectAtWithInt:opt] isKindOfClass:[LibOrgBouncycastleAsn1ASN1Boolean class]]) {
      self->certReq_ = LibOrgBouncycastleAsn1ASN1Boolean_getInstanceWithId_([seq getObjectAtWithInt:opt]);
    }
    else if ([[seq getObjectAtWithInt:opt] isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
      LibOrgBouncycastleAsn1ASN1TaggedObject *tagged = (LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:opt], [LibOrgBouncycastleAsn1ASN1TaggedObject class]);
      if ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(tagged)) getTagNo] == 0) {
        self->extensions_ = LibOrgBouncycastleAsn1X509Extensions_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(tagged, false);
      }
    }
  }
}

LibOrgBouncycastleAsn1TspTimeStampReq *new_LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1TspTimeStampReq, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1TspTimeStampReq *create_LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1TspTimeStampReq, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1TspTimeStampReq *self, LibOrgBouncycastleAsn1TspMessageImprint *messageImprint, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *tsaPolicy, LibOrgBouncycastleAsn1ASN1Integer *nonce, LibOrgBouncycastleAsn1ASN1Boolean *certReq, LibOrgBouncycastleAsn1X509Extensions *extensions) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(1);
  self->messageImprint_ = messageImprint;
  self->tsaPolicy_ = tsaPolicy;
  self->nonce_ = nonce;
  self->certReq_ = certReq;
  self->extensions_ = extensions;
}

LibOrgBouncycastleAsn1TspTimeStampReq *new_LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1TspMessageImprint *messageImprint, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *tsaPolicy, LibOrgBouncycastleAsn1ASN1Integer *nonce, LibOrgBouncycastleAsn1ASN1Boolean *certReq, LibOrgBouncycastleAsn1X509Extensions *extensions) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1TspTimeStampReq, initWithLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1X509Extensions_, messageImprint, tsaPolicy, nonce, certReq, extensions)
}

LibOrgBouncycastleAsn1TspTimeStampReq *create_LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1TspMessageImprint *messageImprint, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *tsaPolicy, LibOrgBouncycastleAsn1ASN1Integer *nonce, LibOrgBouncycastleAsn1ASN1Boolean *certReq, LibOrgBouncycastleAsn1X509Extensions *extensions) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1TspTimeStampReq, initWithLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1X509Extensions_, messageImprint, tsaPolicy, nonce, certReq, extensions)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1TspTimeStampReq)
