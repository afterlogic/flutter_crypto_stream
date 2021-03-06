//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/SignerLocation.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "DERUTF8String.h"
#include "DirectoryString.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "SignerLocation.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1EsfSignerLocation () {
 @public
  LibOrgBouncycastleAsn1X500DirectoryString *countryName_;
  LibOrgBouncycastleAsn1X500DirectoryString *localityName_;
  LibOrgBouncycastleAsn1ASN1Sequence *postalAddress_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (instancetype)initWithLibOrgBouncycastleAsn1X500DirectoryString:(LibOrgBouncycastleAsn1X500DirectoryString *)countryName
                    withLibOrgBouncycastleAsn1X500DirectoryString:(LibOrgBouncycastleAsn1X500DirectoryString *)localityName
                           withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)postalAddress;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfSignerLocation, countryName_, LibOrgBouncycastleAsn1X500DirectoryString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfSignerLocation, localityName_, LibOrgBouncycastleAsn1X500DirectoryString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EsfSignerLocation, postalAddress_, LibOrgBouncycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfSignerLocation *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfSignerLocation *new_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfSignerLocation *create_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static void LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfSignerLocation *self, LibOrgBouncycastleAsn1X500DirectoryString *countryName, LibOrgBouncycastleAsn1X500DirectoryString *localityName, LibOrgBouncycastleAsn1ASN1Sequence *postalAddress);

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfSignerLocation *new_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X500DirectoryString *countryName, LibOrgBouncycastleAsn1X500DirectoryString *localityName, LibOrgBouncycastleAsn1ASN1Sequence *postalAddress) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EsfSignerLocation *create_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X500DirectoryString *countryName, LibOrgBouncycastleAsn1X500DirectoryString *localityName, LibOrgBouncycastleAsn1ASN1Sequence *postalAddress);

@implementation LibOrgBouncycastleAsn1EsfSignerLocation

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X500DirectoryString:(LibOrgBouncycastleAsn1X500DirectoryString *)countryName
                    withLibOrgBouncycastleAsn1X500DirectoryString:(LibOrgBouncycastleAsn1X500DirectoryString *)localityName
                           withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)postalAddress {
  LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1ASN1Sequence_(self, countryName, localityName, postalAddress);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X500DirectoryString:(LibOrgBouncycastleAsn1X500DirectoryString *)countryName
                    withLibOrgBouncycastleAsn1X500DirectoryString:(LibOrgBouncycastleAsn1X500DirectoryString *)localityName
               withLibOrgBouncycastleAsn1X500DirectoryStringArray:(IOSObjectArray *)postalAddress {
  LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryStringArray_(self, countryName, localityName, postalAddress);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1DERUTF8String:(LibOrgBouncycastleAsn1DERUTF8String *)countryName
                    withLibOrgBouncycastleAsn1DERUTF8String:(LibOrgBouncycastleAsn1DERUTF8String *)localityName
                     withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)postalAddress {
  LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1ASN1Sequence_(self, countryName, localityName, postalAddress);
  return self;
}

+ (LibOrgBouncycastleAsn1EsfSignerLocation *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EsfSignerLocation_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1X500DirectoryString *)getCountry {
  return countryName_;
}

- (LibOrgBouncycastleAsn1X500DirectoryString *)getLocality {
  return localityName_;
}

- (IOSObjectArray *)getPostal {
  if (postalAddress_ == nil) {
    return nil;
  }
  IOSObjectArray *dirStrings = [IOSObjectArray newArrayWithLength:[postalAddress_ size] type:LibOrgBouncycastleAsn1X500DirectoryString_class_()];
  for (jint i = 0; i != dirStrings->size_; i++) {
    (void) IOSObjectArray_Set(dirStrings, i, LibOrgBouncycastleAsn1X500DirectoryString_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(postalAddress_)) getObjectAtWithInt:i]));
  }
  return dirStrings;
}

- (LibOrgBouncycastleAsn1DERUTF8String *)getCountryName {
  if (countryName_ == nil) {
    return nil;
  }
  return new_LibOrgBouncycastleAsn1DERUTF8String_initWithNSString_([((LibOrgBouncycastleAsn1X500DirectoryString *) nil_chk([self getCountry])) getString]);
}

- (LibOrgBouncycastleAsn1DERUTF8String *)getLocalityName {
  if (localityName_ == nil) {
    return nil;
  }
  return new_LibOrgBouncycastleAsn1DERUTF8String_initWithNSString_([((LibOrgBouncycastleAsn1X500DirectoryString *) nil_chk([self getLocality])) getString]);
}

- (LibOrgBouncycastleAsn1ASN1Sequence *)getPostalAddress {
  return postalAddress_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  if (countryName_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 0, countryName_)];
  }
  if (localityName_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 1, localityName_)];
  }
  if (postalAddress_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 2, postalAddress_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EsfSignerLocation;", 0x9, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500DirectoryString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500DirectoryString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1X500DirectoryString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERUTF8String;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1DERUTF8String;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Sequence;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1X500DirectoryString:withLibOrgBouncycastleAsn1X500DirectoryString:withLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1X500DirectoryString:withLibOrgBouncycastleAsn1X500DirectoryString:withLibOrgBouncycastleAsn1X500DirectoryStringArray:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1DERUTF8String:withLibOrgBouncycastleAsn1DERUTF8String:withLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(getInstanceWithId:);
  methods[5].selector = @selector(getCountry);
  methods[6].selector = @selector(getLocality);
  methods[7].selector = @selector(getPostal);
  methods[8].selector = @selector(getCountryName);
  methods[9].selector = @selector(getLocalityName);
  methods[10].selector = @selector(getPostalAddress);
  methods[11].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "countryName_", "LLibOrgBouncycastleAsn1X500DirectoryString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "localityName_", "LLibOrgBouncycastleAsn1X500DirectoryString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "postalAddress_", "LLibOrgBouncycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1X500DirectoryString;LLibOrgBouncycastleAsn1X500DirectoryString;LLibOrgBouncycastleAsn1ASN1Sequence;", "LLibOrgBouncycastleAsn1X500DirectoryString;LLibOrgBouncycastleAsn1X500DirectoryString;[LLibOrgBouncycastleAsn1X500DirectoryString;", "LLibOrgBouncycastleAsn1DERUTF8String;LLibOrgBouncycastleAsn1DERUTF8String;LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EsfSignerLocation = { "SignerLocation", "lib.org.bouncycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 12, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EsfSignerLocation;
}

@end

void LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfSignerLocation *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    LibOrgBouncycastleAsn1ASN1TaggedObject *o = (LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1TaggedObject class]);
    switch ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo]) {
      case 0:
      self->countryName_ = LibOrgBouncycastleAsn1X500DirectoryString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
      ;
      break;
      case 1:
      self->localityName_ = LibOrgBouncycastleAsn1X500DirectoryString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
      break;
      case 2:
      if ([o isExplicit]) {
        self->postalAddress_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
      }
      else {
        self->postalAddress_ = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(o, false);
      }
      if (self->postalAddress_ != nil && [self->postalAddress_ size] > 6) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"postal address must contain less than 6 strings");
      }
      break;
      default:
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"illegal tag");
    }
  }
}

LibOrgBouncycastleAsn1EsfSignerLocation *new_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfSignerLocation, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1EsfSignerLocation *create_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfSignerLocation, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

void LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfSignerLocation *self, LibOrgBouncycastleAsn1X500DirectoryString *countryName, LibOrgBouncycastleAsn1X500DirectoryString *localityName, LibOrgBouncycastleAsn1ASN1Sequence *postalAddress) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if (postalAddress != nil && [postalAddress size] > 6) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"postal address must contain less than 6 strings");
  }
  self->countryName_ = countryName;
  self->localityName_ = localityName;
  self->postalAddress_ = postalAddress;
}

LibOrgBouncycastleAsn1EsfSignerLocation *new_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X500DirectoryString *countryName, LibOrgBouncycastleAsn1X500DirectoryString *localityName, LibOrgBouncycastleAsn1ASN1Sequence *postalAddress) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfSignerLocation, initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1ASN1Sequence_, countryName, localityName, postalAddress)
}

LibOrgBouncycastleAsn1EsfSignerLocation *create_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X500DirectoryString *countryName, LibOrgBouncycastleAsn1X500DirectoryString *localityName, LibOrgBouncycastleAsn1ASN1Sequence *postalAddress) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfSignerLocation, initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1ASN1Sequence_, countryName, localityName, postalAddress)
}

void LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryStringArray_(LibOrgBouncycastleAsn1EsfSignerLocation *self, LibOrgBouncycastleAsn1X500DirectoryString *countryName, LibOrgBouncycastleAsn1X500DirectoryString *localityName, IOSObjectArray *postalAddress) {
  LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1ASN1Sequence_(self, countryName, localityName, new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(postalAddress));
}

LibOrgBouncycastleAsn1EsfSignerLocation *new_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryStringArray_(LibOrgBouncycastleAsn1X500DirectoryString *countryName, LibOrgBouncycastleAsn1X500DirectoryString *localityName, IOSObjectArray *postalAddress) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfSignerLocation, initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryStringArray_, countryName, localityName, postalAddress)
}

LibOrgBouncycastleAsn1EsfSignerLocation *create_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryStringArray_(LibOrgBouncycastleAsn1X500DirectoryString *countryName, LibOrgBouncycastleAsn1X500DirectoryString *localityName, IOSObjectArray *postalAddress) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfSignerLocation, initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryStringArray_, countryName, localityName, postalAddress)
}

void LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EsfSignerLocation *self, LibOrgBouncycastleAsn1DERUTF8String *countryName, LibOrgBouncycastleAsn1DERUTF8String *localityName, LibOrgBouncycastleAsn1ASN1Sequence *postalAddress) {
  LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1X500DirectoryString_withLibOrgBouncycastleAsn1ASN1Sequence_(self, LibOrgBouncycastleAsn1X500DirectoryString_getInstanceWithId_(countryName), LibOrgBouncycastleAsn1X500DirectoryString_getInstanceWithId_(localityName), postalAddress);
}

LibOrgBouncycastleAsn1EsfSignerLocation *new_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1DERUTF8String *countryName, LibOrgBouncycastleAsn1DERUTF8String *localityName, LibOrgBouncycastleAsn1ASN1Sequence *postalAddress) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EsfSignerLocation, initWithLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1ASN1Sequence_, countryName, localityName, postalAddress)
}

LibOrgBouncycastleAsn1EsfSignerLocation *create_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1DERUTF8String *countryName, LibOrgBouncycastleAsn1DERUTF8String *localityName, LibOrgBouncycastleAsn1ASN1Sequence *postalAddress) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EsfSignerLocation, initWithLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1DERUTF8String_withLibOrgBouncycastleAsn1ASN1Sequence_, countryName, localityName, postalAddress)
}

LibOrgBouncycastleAsn1EsfSignerLocation *LibOrgBouncycastleAsn1EsfSignerLocation_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EsfSignerLocation_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1EsfSignerLocation class]]) {
    return (LibOrgBouncycastleAsn1EsfSignerLocation *) cast_chk(obj, [LibOrgBouncycastleAsn1EsfSignerLocation class]);
  }
  return new_LibOrgBouncycastleAsn1EsfSignerLocation_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EsfSignerLocation)
