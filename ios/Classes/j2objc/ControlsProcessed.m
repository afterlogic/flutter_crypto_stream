//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/ControlsProcessed.java
//

#include "ASN1Encodable.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "BodyPartReference.h"
#include "ControlsProcessed.h"
#include "DERSequence.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CmcControlsProcessed () {
 @public
  LibOrgBouncycastleAsn1ASN1Sequence *bodyPartReferences_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmcControlsProcessed, bodyPartReferences_, LibOrgBouncycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcControlsProcessed *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcControlsProcessed *new_LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CmcControlsProcessed *create_LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CmcControlsProcessed

- (instancetype)initWithLibOrgBouncycastleAsn1CmcBodyPartReference:(LibOrgBouncycastleAsn1CmcBodyPartReference *)bodyPartRef {
  LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1CmcBodyPartReference_(self, bodyPartRef);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1CmcBodyPartReferenceArray:(IOSObjectArray *)bodyList {
  LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1CmcBodyPartReferenceArray_(self, bodyList);
  return self;
}

+ (LibOrgBouncycastleAsn1CmcControlsProcessed *)getInstanceWithId:(id)src {
  return LibOrgBouncycastleAsn1CmcControlsProcessed_getInstanceWithId_(src);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (IOSObjectArray *)getBodyList {
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(bodyPartReferences_)) size] type:LibOrgBouncycastleAsn1CmcBodyPartReference_class_()];
  for (jint i = 0; i != [bodyPartReferences_ size]; i++) {
    (void) IOSObjectArray_Set(tmp, i, LibOrgBouncycastleAsn1CmcBodyPartReference_getInstanceWithId_([bodyPartReferences_ getObjectAtWithInt:i]));
  }
  return tmp;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(bodyPartReferences_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CmcControlsProcessed;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 4, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1CmcBodyPartReference;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1CmcBodyPartReference:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1CmcBodyPartReferenceArray:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(getBodyList);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bodyPartReferences_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1CmcBodyPartReference;", "[LLibOrgBouncycastleAsn1CmcBodyPartReference;", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CmcControlsProcessed = { "ControlsProcessed", "lib.org.bouncycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CmcControlsProcessed;
}

@end

void LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1CmcBodyPartReference_(LibOrgBouncycastleAsn1CmcControlsProcessed *self, LibOrgBouncycastleAsn1CmcBodyPartReference *bodyPartRef) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->bodyPartReferences_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1Encodable_(bodyPartRef);
}

LibOrgBouncycastleAsn1CmcControlsProcessed *new_LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1CmcBodyPartReference_(LibOrgBouncycastleAsn1CmcBodyPartReference *bodyPartRef) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcControlsProcessed, initWithLibOrgBouncycastleAsn1CmcBodyPartReference_, bodyPartRef)
}

LibOrgBouncycastleAsn1CmcControlsProcessed *create_LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1CmcBodyPartReference_(LibOrgBouncycastleAsn1CmcBodyPartReference *bodyPartRef) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcControlsProcessed, initWithLibOrgBouncycastleAsn1CmcBodyPartReference_, bodyPartRef)
}

void LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1CmcBodyPartReferenceArray_(LibOrgBouncycastleAsn1CmcControlsProcessed *self, IOSObjectArray *bodyList) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->bodyPartReferences_ = new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(bodyList);
}

LibOrgBouncycastleAsn1CmcControlsProcessed *new_LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1CmcBodyPartReferenceArray_(IOSObjectArray *bodyList) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcControlsProcessed, initWithLibOrgBouncycastleAsn1CmcBodyPartReferenceArray_, bodyList)
}

LibOrgBouncycastleAsn1CmcControlsProcessed *create_LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1CmcBodyPartReferenceArray_(IOSObjectArray *bodyList) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcControlsProcessed, initWithLibOrgBouncycastleAsn1CmcBodyPartReferenceArray_, bodyList)
}

LibOrgBouncycastleAsn1CmcControlsProcessed *LibOrgBouncycastleAsn1CmcControlsProcessed_getInstanceWithId_(id src) {
  LibOrgBouncycastleAsn1CmcControlsProcessed_initialize();
  if ([src isKindOfClass:[LibOrgBouncycastleAsn1CmcControlsProcessed class]]) {
    return (LibOrgBouncycastleAsn1CmcControlsProcessed *) src;
  }
  else if (src != nil) {
    return new_LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(src));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmcControlsProcessed *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 1) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->bodyPartReferences_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([seq getObjectAtWithInt:0]);
}

LibOrgBouncycastleAsn1CmcControlsProcessed *new_LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CmcControlsProcessed, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CmcControlsProcessed *create_LibOrgBouncycastleAsn1CmcControlsProcessed_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CmcControlsProcessed, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CmcControlsProcessed)