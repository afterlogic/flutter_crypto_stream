//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/SignerAttribute.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "AttributeCertificate.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "SignerAttribute.h"
#include "X509Attribute.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1EsfSignerAttribute () {
 @public
  IOSObjectArray *values_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfSignerAttribute, values_, IOSObjectArray *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfSignerAttribute *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfSignerAttribute *new_LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfSignerAttribute *create_LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1EsfSignerAttribute

+ (LibOrgBouncycastleAsn1EsfSignerAttribute *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1EsfSignerAttribute_getInstanceWithId_(o);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509X509AttributeArray:(IOSObjectArray *)claimedAttributes {
  LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1X509X509AttributeArray_(self, claimedAttributes);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509AttributeCertificate:(LibOrgBouncycastleAsn1X509AttributeCertificate *)certifiedAttributes {
  LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1X509AttributeCertificate_(self, certifiedAttributes);
  return self;
}

- (IOSObjectArray *)getValues {
  IOSObjectArray *rv = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(values_))->size_ type:NSObject_class_()];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(values_, 0, rv, 0, rv->size_);
  return rv;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(values_))->size_; i++) {
    if ([IOSClass_arrayType(LibOrgBouncycastleAsn1X509X509Attribute_class_(), 1) isInstance:IOSObjectArray_Get(values_, i)]) {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(0, new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_((IOSObjectArray *) cast_check(IOSObjectArray_Get(values_, i), IOSClass_arrayType(LibOrgBouncycastleAsn1X509X509Attribute_class_(), 1))))];
    }
    else {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(1, (LibOrgBouncycastleAsn1X509AttributeCertificate *) cast_chk(IOSObjectArray_Get(values_, i), [LibOrgBouncycastleAsn1X509AttributeCertificate class]))];
    }
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1EsfSignerAttribute;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "[LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1X509X509AttributeArray:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1X509AttributeCertificate:);
  methods[4].selector = @selector(getValues);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "values_", "[LNSObject;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "[LLibOrgBouncycastleAsn1X509X509Attribute;", "LLibOrgBouncycastleAsn1X509AttributeCertificate;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EsfSignerAttribute = { "SignerAttribute", "lib.org.bouncycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EsfSignerAttribute;
}

@end

LibOrgBouncycastleAsn1EsfSignerAttribute *LibOrgBouncycastleAsn1EsfSignerAttribute_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1EsfSignerAttribute_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1EsfSignerAttribute class]]) {
    return (LibOrgBouncycastleAsn1EsfSignerAttribute *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfSignerAttribute *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  jint index = 0;
  self->values_ = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] type:NSObject_class_()];
  for (id<JavaUtilEnumeration> e = [seq getObjects]; [((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]; ) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *taggedObject = LibOrgBouncycastleAsn1ASN1TaggedObject_getInstanceWithId_([e nextElement]);
    if ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(taggedObject)) getTagNo] == 0) {
      LibOrgBouncycastleAsn1ASN1Sequence *attrs = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(taggedObject, true);
      IOSObjectArray *attributes = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(attrs)) size] type:LibOrgBouncycastleAsn1X509X509Attribute_class_()];
      for (jint i = 0; i != attributes->size_; i++) {
        (void) IOSObjectArray_Set(attributes, i, LibOrgBouncycastleAsn1X509X509Attribute_getInstanceWithId_([attrs getObjectAtWithInt:i]));
      }
      (void) IOSObjectArray_Set(nil_chk(self->values_), index, attributes);
    }
    else if ([taggedObject getTagNo] == 1) {
      (void) IOSObjectArray_Set(nil_chk(self->values_), index, LibOrgBouncycastleAsn1X509AttributeCertificate_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(taggedObject, true)));
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"illegal tag: ", [taggedObject getTagNo]));
    }
    index++;
  }
}

LibOrgBouncycastleAsn1EsfSignerAttribute *new_LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfSignerAttribute, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1EsfSignerAttribute *create_LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfSignerAttribute, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1X509X509AttributeArray_(LibOrgBouncycastleAsn1EsfSignerAttribute *self, IOSObjectArray *claimedAttributes) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->values_ = [IOSObjectArray newArrayWithLength:1 type:NSObject_class_()];
  (void) IOSObjectArray_Set(self->values_, 0, claimedAttributes);
}

LibOrgBouncycastleAsn1EsfSignerAttribute *new_LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1X509X509AttributeArray_(IOSObjectArray *claimedAttributes) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfSignerAttribute, initWithLibOrgBouncycastleAsn1X509X509AttributeArray_, claimedAttributes)
}

LibOrgBouncycastleAsn1EsfSignerAttribute *create_LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1X509X509AttributeArray_(IOSObjectArray *claimedAttributes) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfSignerAttribute, initWithLibOrgBouncycastleAsn1X509X509AttributeArray_, claimedAttributes)
}

void LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1X509AttributeCertificate_(LibOrgBouncycastleAsn1EsfSignerAttribute *self, LibOrgBouncycastleAsn1X509AttributeCertificate *certifiedAttributes) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->values_ = [IOSObjectArray newArrayWithLength:1 type:NSObject_class_()];
  (void) IOSObjectArray_Set(self->values_, 0, certifiedAttributes);
}

LibOrgBouncycastleAsn1EsfSignerAttribute *new_LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1X509AttributeCertificate_(LibOrgBouncycastleAsn1X509AttributeCertificate *certifiedAttributes) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfSignerAttribute, initWithLibOrgBouncycastleAsn1X509AttributeCertificate_, certifiedAttributes)
}

LibOrgBouncycastleAsn1EsfSignerAttribute *create_LibOrgBouncycastleAsn1EsfSignerAttribute_initWithLibOrgBouncycastleAsn1X509AttributeCertificate_(LibOrgBouncycastleAsn1X509AttributeCertificate *certifiedAttributes) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfSignerAttribute, initWithLibOrgBouncycastleAsn1X509AttributeCertificate_, certifiedAttributes)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EsfSignerAttribute)
