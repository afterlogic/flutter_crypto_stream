//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/isismtt/x509/AdditionalInformationSyntax.java
//

#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "AdditionalInformationSyntax.h"
#include "DirectoryString.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax () {
 @public
  LibOrgBouncycastleAsn1X500DirectoryString *information_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X500DirectoryString:(LibOrgBouncycastleAsn1X500DirectoryString *)information;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax, information_, LibOrgBouncycastleAsn1X500DirectoryString *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithLibOrgBouncycastleAsn1X500DirectoryString_(LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *self, LibOrgBouncycastleAsn1X500DirectoryString *information);

__attribute__((unused)) static LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *new_LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithLibOrgBouncycastleAsn1X500DirectoryString_(LibOrgBouncycastleAsn1X500DirectoryString *information) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *create_LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithLibOrgBouncycastleAsn1X500DirectoryString_(LibOrgBouncycastleAsn1X500DirectoryString *information);

@implementation LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax

+ (LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1X500DirectoryString:(LibOrgBouncycastleAsn1X500DirectoryString *)information {
  LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithLibOrgBouncycastleAsn1X500DirectoryString_(self, information);
  return self;
}

- (instancetype)initWithNSString:(NSString *)information {
  LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithNSString_(self, information);
  return self;
}

- (LibOrgBouncycastleAsn1X500DirectoryString *)getInformation {
  return information_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  return [((LibOrgBouncycastleAsn1X500DirectoryString *) nil_chk(information_)) toASN1Primitive];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X500DirectoryString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1X500DirectoryString:);
  methods[2].selector = @selector(initWithNSString:);
  methods[3].selector = @selector(getInformation);
  methods[4].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "information_", "LLibOrgBouncycastleAsn1X500DirectoryString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1X500DirectoryString;", "LNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax = { "AdditionalInformationSyntax", "lib.org.bouncycastle.asn1.isismtt.x509", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax;
}

@end

LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax class]]) {
    return (LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithLibOrgBouncycastleAsn1X500DirectoryString_(LibOrgBouncycastleAsn1X500DirectoryString_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithLibOrgBouncycastleAsn1X500DirectoryString_(LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *self, LibOrgBouncycastleAsn1X500DirectoryString *information) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->information_ = information;
}

LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *new_LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithLibOrgBouncycastleAsn1X500DirectoryString_(LibOrgBouncycastleAsn1X500DirectoryString *information) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax, initWithLibOrgBouncycastleAsn1X500DirectoryString_, information)
}

LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *create_LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithLibOrgBouncycastleAsn1X500DirectoryString_(LibOrgBouncycastleAsn1X500DirectoryString *information) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax, initWithLibOrgBouncycastleAsn1X500DirectoryString_, information)
}

void LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithNSString_(LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *self, NSString *information) {
  LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithLibOrgBouncycastleAsn1X500DirectoryString_(self, new_LibOrgBouncycastleAsn1X500DirectoryString_initWithNSString_(information));
}

LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *new_LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithNSString_(NSString *information) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax, initWithNSString_, information)
}

LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax *create_LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax_initWithNSString_(NSString *information) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax, initWithNSString_, information)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1IsismttX509AdditionalInformationSyntax)
