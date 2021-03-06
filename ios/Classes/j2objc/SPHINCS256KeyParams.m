//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/asn1/SPHINCS256KeyParams.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "AlgorithmIdentifier.h"
#include "DERSequence.h"
#include "J2ObjC_source.h"
#include "SPHINCS256KeyParams.h"

@interface LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *version__;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *treeDigest_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)sequence;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams, version__, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams, treeDigest_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)

__attribute__((unused)) static void LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *self, LibOrgBouncycastleAsn1ASN1Sequence *sequence);

__attribute__((unused)) static LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *new_LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *sequence) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *create_LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *sequence);

@implementation LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams

- (instancetype)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)treeDigest {
  LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(self, treeDigest);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)sequence {
  LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, sequence);
  return self;
}

+ (LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *)getInstanceWithId:(id)o {
  return LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_getInstanceWithId_(o);
}

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getTreeDigest {
  return treeDigest_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:version__];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:treeDigest_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcAsn1SPHINCS256KeyParams;", 0x19, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getTreeDigest);
  methods[4].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x12, 4, -1, -1, -1 },
    { "treeDigest_", "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1X509AlgorithmIdentifier;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams = { "SPHINCS256KeyParams", "lib.org.bouncycastle.pqc.asn1", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams;
}

@end

void LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *treeDigest) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(0);
  self->treeDigest_ = treeDigest;
}

LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *new_LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *treeDigest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_, treeDigest)
}

LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *create_LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *treeDigest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams, initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_, treeDigest)
}

void LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *self, LibOrgBouncycastleAsn1ASN1Sequence *sequence) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->version__ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(sequence)) getObjectAtWithInt:0]);
  self->treeDigest_ = LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([sequence getObjectAtWithInt:1]);
}

LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *new_LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *sequence) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams, initWithLibOrgBouncycastleAsn1ASN1Sequence_, sequence)
}

LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *create_LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *sequence) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams, initWithLibOrgBouncycastleAsn1ASN1Sequence_, sequence)
}

LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_getInstanceWithId_(id o) {
  LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams class]]) {
    return (LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcAsn1SPHINCS256KeyParams)
