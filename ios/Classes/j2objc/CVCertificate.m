//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/eac/CVCertificate.java
//

#include "ASN1ApplicationSpecific.h"
#include "ASN1EncodableVector.h"
#include "ASN1InputStream.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1ParsingException.h"
#include "ASN1Primitive.h"
#include "Arrays.h"
#include "CVCertificate.h"
#include "CertificateBody.h"
#include "CertificateHolderAuthorization.h"
#include "CertificateHolderReference.h"
#include "CertificationAuthorityReference.h"
#include "DERApplicationSpecific.h"
#include "DEROctetString.h"
#include "EACTags.h"
#include "Flags.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PackedDate.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalStateException.h"

@interface LibOrgBouncycastleAsn1EacCVCertificate () {
 @public
  LibOrgBouncycastleAsn1EacCertificateBody *certificateBody_;
  IOSByteArray *signature_;
  jint valid_;
}

- (void)setPrivateDataWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *)appSpe;

- (void)initFromWithLibOrgBouncycastleAsn1ASN1InputStream:(LibOrgBouncycastleAsn1ASN1InputStream *)aIS OBJC_METHOD_FAMILY_NONE;

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *)appSpe;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EacCVCertificate, certificateBody_, LibOrgBouncycastleAsn1EacCertificateBody *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EacCVCertificate, signature_, IOSByteArray *)

inline jint LibOrgBouncycastleAsn1EacCVCertificate_get_bodyValid(void);
inline jint LibOrgBouncycastleAsn1EacCVCertificate_set_bodyValid(jint value);
inline jint *LibOrgBouncycastleAsn1EacCVCertificate_getRef_bodyValid(void);
static jint LibOrgBouncycastleAsn1EacCVCertificate_bodyValid = 1;
J2OBJC_STATIC_FIELD_PRIMITIVE(LibOrgBouncycastleAsn1EacCVCertificate, bodyValid, jint)

inline jint LibOrgBouncycastleAsn1EacCVCertificate_get_signValid(void);
inline jint LibOrgBouncycastleAsn1EacCVCertificate_set_signValid(jint value);
inline jint *LibOrgBouncycastleAsn1EacCVCertificate_getRef_signValid(void);
static jint LibOrgBouncycastleAsn1EacCVCertificate_signValid = 2;
J2OBJC_STATIC_FIELD_PRIMITIVE(LibOrgBouncycastleAsn1EacCVCertificate, signValid, jint)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EacCVCertificate_setPrivateDataWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1EacCVCertificate *self, LibOrgBouncycastleAsn1ASN1ApplicationSpecific *appSpe);

__attribute__((unused)) static void LibOrgBouncycastleAsn1EacCVCertificate_initFromWithLibOrgBouncycastleAsn1ASN1InputStream_(LibOrgBouncycastleAsn1EacCVCertificate *self, LibOrgBouncycastleAsn1ASN1InputStream *aIS);

__attribute__((unused)) static void LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1EacCVCertificate *self, LibOrgBouncycastleAsn1ASN1ApplicationSpecific *appSpe);

__attribute__((unused)) static LibOrgBouncycastleAsn1EacCVCertificate *new_LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *appSpe) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EacCVCertificate *create_LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *appSpe);

@implementation LibOrgBouncycastleAsn1EacCVCertificate

- (void)setPrivateDataWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *)appSpe {
  LibOrgBouncycastleAsn1EacCVCertificate_setPrivateDataWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(self, appSpe);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1InputStream:(LibOrgBouncycastleAsn1ASN1InputStream *)aIS {
  LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1InputStream_(self, aIS);
  return self;
}

- (void)initFromWithLibOrgBouncycastleAsn1ASN1InputStream:(LibOrgBouncycastleAsn1ASN1InputStream *)aIS {
  LibOrgBouncycastleAsn1EacCVCertificate_initFromWithLibOrgBouncycastleAsn1ASN1InputStream_(self, aIS);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *)appSpe {
  LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(self, appSpe);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1EacCertificateBody:(LibOrgBouncycastleAsn1EacCertificateBody *)body
                                                   withByteArray:(IOSByteArray *)signature {
  LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1EacCertificateBody_withByteArray_(self, body, signature);
  return self;
}

+ (LibOrgBouncycastleAsn1EacCVCertificate *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EacCVCertificate_getInstanceWithId_(obj);
}

- (IOSByteArray *)getSignature {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(signature_);
}

- (LibOrgBouncycastleAsn1EacCertificateBody *)getBody {
  return certificateBody_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certificateBody_];
  @try {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERApplicationSpecific_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, LibOrgBouncycastleAsn1EacEACTags_STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP, new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(signature_))];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"unable to convert signature!");
  }
  return new_LibOrgBouncycastleAsn1DERApplicationSpecific_initWithInt_withLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1EacEACTags_CARDHOLDER_CERTIFICATE, v);
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getHolderAuthorization {
  LibOrgBouncycastleAsn1EacCertificateHolderAuthorization *cha = [((LibOrgBouncycastleAsn1EacCertificateBody *) nil_chk(certificateBody_)) getCertificateHolderAuthorization];
  return [((LibOrgBouncycastleAsn1EacCertificateHolderAuthorization *) nil_chk(cha)) getOid];
}

- (LibOrgBouncycastleAsn1EacPackedDate *)getEffectiveDate {
  return [((LibOrgBouncycastleAsn1EacCertificateBody *) nil_chk(certificateBody_)) getCertificateEffectiveDate];
}

- (jint)getCertificateType {
  return [((LibOrgBouncycastleAsn1EacCertificateBody *) nil_chk(self->certificateBody_)) getCertificateType];
}

- (LibOrgBouncycastleAsn1EacPackedDate *)getExpirationDate {
  return [((LibOrgBouncycastleAsn1EacCertificateBody *) nil_chk(certificateBody_)) getCertificateExpirationDate];
}

- (jint)getRole {
  LibOrgBouncycastleAsn1EacCertificateHolderAuthorization *cha = [((LibOrgBouncycastleAsn1EacCertificateBody *) nil_chk(certificateBody_)) getCertificateHolderAuthorization];
  return [((LibOrgBouncycastleAsn1EacCertificateHolderAuthorization *) nil_chk(cha)) getAccessRights];
}

- (LibOrgBouncycastleAsn1EacCertificationAuthorityReference *)getAuthorityReference {
  return [((LibOrgBouncycastleAsn1EacCertificateBody *) nil_chk(certificateBody_)) getCertificationAuthorityReference];
}

- (LibOrgBouncycastleAsn1EacCertificateHolderReference *)getHolderReference {
  return [((LibOrgBouncycastleAsn1EacCertificateBody *) nil_chk(certificateBody_)) getCertificateHolderReference];
}

- (jint)getHolderAuthorizationRole {
  jint rights = [((LibOrgBouncycastleAsn1EacCertificateHolderAuthorization *) nil_chk([((LibOrgBouncycastleAsn1EacCertificateBody *) nil_chk(certificateBody_)) getCertificateHolderAuthorization])) getAccessRights];
  return rights & (jint) 0xC0;
}

- (LibOrgBouncycastleAsn1EacFlags *)getHolderAuthorizationRights {
  return new_LibOrgBouncycastleAsn1EacFlags_initWithInt_([((LibOrgBouncycastleAsn1EacCertificateHolderAuthorization *) nil_chk([((LibOrgBouncycastleAsn1EacCertificateBody *) nil_chk(certificateBody_)) getCertificateHolderAuthorization])) getAccessRights] & (jint) 0x1F);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x2, 0, 1, 2, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, 2, -1, -1, -1 },
    { NULL, "V", 0x2, 4, 3, 2, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, 2, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EacCVCertificate;", 0x9, 6, 7, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EacCertificateBody;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EacPackedDate;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EacPackedDate;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EacCertificationAuthorityReference;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EacCertificateHolderReference;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EacFlags;", 0x1, -1, -1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(setPrivateDataWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1InputStream:);
  methods[2].selector = @selector(initFromWithLibOrgBouncycastleAsn1ASN1InputStream:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1EacCertificateBody:withByteArray:);
  methods[5].selector = @selector(getInstanceWithId:);
  methods[6].selector = @selector(getSignature);
  methods[7].selector = @selector(getBody);
  methods[8].selector = @selector(toASN1Primitive);
  methods[9].selector = @selector(getHolderAuthorization);
  methods[10].selector = @selector(getEffectiveDate);
  methods[11].selector = @selector(getCertificateType);
  methods[12].selector = @selector(getExpirationDate);
  methods[13].selector = @selector(getRole);
  methods[14].selector = @selector(getAuthorityReference);
  methods[15].selector = @selector(getHolderReference);
  methods[16].selector = @selector(getHolderAuthorizationRole);
  methods[17].selector = @selector(getHolderAuthorizationRights);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "certificateBody_", "LLibOrgBouncycastleAsn1EacCertificateBody;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "signature_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "valid_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "bodyValid", "I", .constantValue.asLong = 0, 0xa, -1, 8, -1, -1 },
    { "signValid", "I", .constantValue.asLong = 0, 0xa, -1, 9, -1, -1 },
  };
  static const void *ptrTable[] = { "setPrivateData", "LLibOrgBouncycastleAsn1ASN1ApplicationSpecific;", "LJavaIoIOException;", "LLibOrgBouncycastleAsn1ASN1InputStream;", "initFrom", "LLibOrgBouncycastleAsn1EacCertificateBody;[B", "getInstance", "LNSObject;", &LibOrgBouncycastleAsn1EacCVCertificate_bodyValid, &LibOrgBouncycastleAsn1EacCVCertificate_signValid };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EacCVCertificate = { "CVCertificate", "lib.org.bouncycastle.asn1.eac", ptrTable, methods, fields, 7, 0x1, 18, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EacCVCertificate;
}

@end

void LibOrgBouncycastleAsn1EacCVCertificate_setPrivateDataWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1EacCVCertificate *self, LibOrgBouncycastleAsn1ASN1ApplicationSpecific *appSpe) {
  self->valid_ = 0;
  if ([((LibOrgBouncycastleAsn1ASN1ApplicationSpecific *) nil_chk(appSpe)) getApplicationTag] == LibOrgBouncycastleAsn1EacEACTags_CARDHOLDER_CERTIFICATE) {
    LibOrgBouncycastleAsn1ASN1InputStream *content = new_LibOrgBouncycastleAsn1ASN1InputStream_initWithByteArray_([appSpe getContents]);
    LibOrgBouncycastleAsn1ASN1Primitive *tmpObj;
    while ((tmpObj = [content readObject]) != nil) {
      LibOrgBouncycastleAsn1ASN1ApplicationSpecific *aSpe;
      if ([tmpObj isKindOfClass:[LibOrgBouncycastleAsn1ASN1ApplicationSpecific class]]) {
        aSpe = (LibOrgBouncycastleAsn1ASN1ApplicationSpecific *) tmpObj;
        switch ([((LibOrgBouncycastleAsn1ASN1ApplicationSpecific *) nil_chk(aSpe)) getApplicationTag]) {
          case LibOrgBouncycastleAsn1EacEACTags_CERTIFICATE_CONTENT_TEMPLATE:
          self->certificateBody_ = LibOrgBouncycastleAsn1EacCertificateBody_getInstanceWithId_(aSpe);
          self->valid_ |= LibOrgBouncycastleAsn1EacCVCertificate_bodyValid;
          break;
          case LibOrgBouncycastleAsn1EacEACTags_STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP:
          self->signature_ = [aSpe getContents];
          self->valid_ |= LibOrgBouncycastleAsn1EacCVCertificate_signValid;
          break;
          default:
          @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$I", @"Invalid tag, not an Iso7816CertificateStructure :", [aSpe getApplicationTag]));
        }
      }
      else {
        @throw new_JavaIoIOException_initWithNSString_(@"Invalid Object, not an Iso7816CertificateStructure");
      }
    }
    [content close];
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$I", @"not a CARDHOLDER_CERTIFICATE :", [appSpe getApplicationTag]));
  }
  if (self->valid_ != (LibOrgBouncycastleAsn1EacCVCertificate_signValid | LibOrgBouncycastleAsn1EacCVCertificate_bodyValid)) {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$I", @"invalid CARDHOLDER_CERTIFICATE :", [appSpe getApplicationTag]));
  }
}

void LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1InputStream_(LibOrgBouncycastleAsn1EacCVCertificate *self, LibOrgBouncycastleAsn1ASN1InputStream *aIS) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  LibOrgBouncycastleAsn1EacCVCertificate_initFromWithLibOrgBouncycastleAsn1ASN1InputStream_(self, aIS);
}

LibOrgBouncycastleAsn1EacCVCertificate *new_LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1InputStream_(LibOrgBouncycastleAsn1ASN1InputStream *aIS) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EacCVCertificate, initWithLibOrgBouncycastleAsn1ASN1InputStream_, aIS)
}

LibOrgBouncycastleAsn1EacCVCertificate *create_LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1InputStream_(LibOrgBouncycastleAsn1ASN1InputStream *aIS) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EacCVCertificate, initWithLibOrgBouncycastleAsn1ASN1InputStream_, aIS)
}

void LibOrgBouncycastleAsn1EacCVCertificate_initFromWithLibOrgBouncycastleAsn1ASN1InputStream_(LibOrgBouncycastleAsn1EacCVCertificate *self, LibOrgBouncycastleAsn1ASN1InputStream *aIS) {
  LibOrgBouncycastleAsn1ASN1Primitive *obj;
  while ((obj = [((LibOrgBouncycastleAsn1ASN1InputStream *) nil_chk(aIS)) readObject]) != nil) {
    if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1ApplicationSpecific class]]) {
      LibOrgBouncycastleAsn1EacCVCertificate_setPrivateDataWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(self, (LibOrgBouncycastleAsn1ASN1ApplicationSpecific *) obj);
    }
    else {
      @throw new_JavaIoIOException_initWithNSString_(@"Invalid Input Stream for creating an Iso7816CertificateStructure");
    }
  }
}

void LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1EacCVCertificate *self, LibOrgBouncycastleAsn1ASN1ApplicationSpecific *appSpe) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  LibOrgBouncycastleAsn1EacCVCertificate_setPrivateDataWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(self, appSpe);
}

LibOrgBouncycastleAsn1EacCVCertificate *new_LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *appSpe) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EacCVCertificate, initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_, appSpe)
}

LibOrgBouncycastleAsn1EacCVCertificate *create_LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *appSpe) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EacCVCertificate, initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_, appSpe)
}

void LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1EacCertificateBody_withByteArray_(LibOrgBouncycastleAsn1EacCVCertificate *self, LibOrgBouncycastleAsn1EacCertificateBody *body, IOSByteArray *signature) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->certificateBody_ = body;
  self->signature_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(signature);
  self->valid_ |= LibOrgBouncycastleAsn1EacCVCertificate_bodyValid;
  self->valid_ |= LibOrgBouncycastleAsn1EacCVCertificate_signValid;
}

LibOrgBouncycastleAsn1EacCVCertificate *new_LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1EacCertificateBody_withByteArray_(LibOrgBouncycastleAsn1EacCertificateBody *body, IOSByteArray *signature) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EacCVCertificate, initWithLibOrgBouncycastleAsn1EacCertificateBody_withByteArray_, body, signature)
}

LibOrgBouncycastleAsn1EacCVCertificate *create_LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1EacCertificateBody_withByteArray_(LibOrgBouncycastleAsn1EacCertificateBody *body, IOSByteArray *signature) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EacCVCertificate, initWithLibOrgBouncycastleAsn1EacCertificateBody_withByteArray_, body, signature)
}

LibOrgBouncycastleAsn1EacCVCertificate *LibOrgBouncycastleAsn1EacCVCertificate_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EacCVCertificate_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1EacCVCertificate class]]) {
    return (LibOrgBouncycastleAsn1EacCVCertificate *) obj;
  }
  else if (obj != nil) {
    @try {
      return new_LibOrgBouncycastleAsn1EacCVCertificate_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific_getInstanceWithId_(obj));
    }
    @catch (JavaIoIOException *e) {
      @throw new_LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"unable to parse data: ", [e getMessage]), e);
    }
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EacCVCertificate)
