//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/bc/EncryptedPrivateKeyData.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DERSequence.h"
#include "EncryptedPrivateKeyData.h"
#include "EncryptedPrivateKeyInfo.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "X509Certificate.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData () {
 @public
  LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *encryptedPrivateKeyInfo_;
  IOSObjectArray *certificateChain_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData, encryptedPrivateKeyInfo_, LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData, certificateChain_, IOSObjectArray *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *new_LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *create_LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData

- (instancetype)initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *)encryptedPrivateKeyInfo
                       withLibOrgBouncycastleAsn1X509X509CertificateArray:(IOSObjectArray *)certificateChain {
  LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_withLibOrgBouncycastleAsn1X509X509CertificateArray_(self, encryptedPrivateKeyInfo, certificateChain);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_getInstanceWithId_(o);
}

- (IOSObjectArray *)getCertificateChain {
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(certificateChain_))->size_ type:LibOrgBouncycastleAsn1X509X509Certificate_class_()];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(certificateChain_, 0, tmp, 0, certificateChain_->size_);
  return tmp;
}

- (LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *)getEncryptedPrivateKeyInfo {
  return encryptedPrivateKeyInfo_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:encryptedPrivateKeyInfo_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableArray_(certificateChain_)];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1BcEncryptedPrivateKeyData;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1X509X509Certificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo:withLibOrgBouncycastleAsn1X509X509CertificateArray:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getCertificateChain);
  methods[4].selector = @selector(getEncryptedPrivateKeyInfo);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "encryptedPrivateKeyInfo_", "LLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "certificateChain_", "[LLibOrgBouncycastleAsn1X509X509Certificate;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo;[LLibOrgBouncycastleAsn1X509X509Certificate;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData = { "EncryptedPrivateKeyData", "lib.org.bouncycastle.asn1.bc", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData;
}

@end

void LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_withLibOrgBouncycastleAsn1X509X509CertificateArray_(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *self, LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *encryptedPrivateKeyInfo, IOSObjectArray *certificateChain) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->encryptedPrivateKeyInfo_ = encryptedPrivateKeyInfo;
  self->certificateChain_ = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(certificateChain))->size_ type:LibOrgBouncycastleAsn1X509X509Certificate_class_()];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(certificateChain, 0, self->certificateChain_, 0, certificateChain->size_);
}

LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *new_LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_withLibOrgBouncycastleAsn1X509X509CertificateArray_(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *encryptedPrivateKeyInfo, IOSObjectArray *certificateChain) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData, initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_withLibOrgBouncycastleAsn1X509X509CertificateArray_, encryptedPrivateKeyInfo, certificateChain)
}

LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *create_LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_withLibOrgBouncycastleAsn1X509X509CertificateArray_(LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo *encryptedPrivateKeyInfo, IOSObjectArray *certificateChain) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData, initWithLibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_withLibOrgBouncycastleAsn1X509X509CertificateArray_, encryptedPrivateKeyInfo, certificateChain)
}

void LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->encryptedPrivateKeyInfo_ = LibOrgBouncycastleAsn1PkcsEncryptedPrivateKeyInfo_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  LibOrgBouncycastleAsn1ASN1Sequence *certSeq = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([seq getObjectAtWithInt:1]);
  self->certificateChain_ = [IOSObjectArray newArrayWithLength:[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(certSeq)) size] type:LibOrgBouncycastleAsn1X509X509Certificate_class_()];
  for (jint i = 0; i != self->certificateChain_->size_; i++) {
    (void) IOSObjectArray_Set(self->certificateChain_, i, LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithId_([certSeq getObjectAtWithInt:i]));
  }
}

LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *new_LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *create_LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData class]]) {
    return (LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1BcEncryptedPrivateKeyData)