//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/Certificate.java
//

#include "ASN1Encoding.h"
#include "ASN1Primitive.h"
#include "Certificate.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "TlsUtils.h"
#include "X509Certificate.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/util/Vector.h"

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoTlsCertificate)

LibOrgBouncycastleCryptoTlsCertificate *LibOrgBouncycastleCryptoTlsCertificate_EMPTY_CHAIN;

@implementation LibOrgBouncycastleCryptoTlsCertificate

+ (LibOrgBouncycastleCryptoTlsCertificate *)EMPTY_CHAIN {
  return LibOrgBouncycastleCryptoTlsCertificate_EMPTY_CHAIN;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509X509CertificateArray:(IOSObjectArray *)certificateList {
  LibOrgBouncycastleCryptoTlsCertificate_initWithLibOrgBouncycastleAsn1X509X509CertificateArray_(self, certificateList);
  return self;
}

- (IOSObjectArray *)getCertificateList {
  return [self cloneCertificateList];
}

- (LibOrgBouncycastleAsn1X509X509Certificate *)getCertificateAtWithInt:(jint)index {
  return IOSObjectArray_Get(nil_chk(certificateList_), index);
}

- (jint)getLength {
  return ((IOSObjectArray *) nil_chk(certificateList_))->size_;
}

- (jboolean)isEmpty {
  return ((IOSObjectArray *) nil_chk(certificateList_))->size_ == 0;
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  JavaUtilVector *derEncodings = new_JavaUtilVector_initWithInt_(((IOSObjectArray *) nil_chk(self->certificateList_))->size_);
  jint totalLength = 0;
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(self->certificateList_))->size_; ++i) {
    IOSByteArray *derEncoding = [((LibOrgBouncycastleAsn1X509X509Certificate *) nil_chk(IOSObjectArray_Get(certificateList_, i))) getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
    [derEncodings addElementWithId:derEncoding];
    totalLength += ((IOSByteArray *) nil_chk(derEncoding))->size_ + 3;
  }
  LibOrgBouncycastleCryptoTlsTlsUtils_checkUint24WithInt_(totalLength);
  LibOrgBouncycastleCryptoTlsTlsUtils_writeUint24WithInt_withJavaIoOutputStream_(totalLength, output);
  for (jint i = 0; i < [derEncodings size]; ++i) {
    IOSByteArray *derEncoding = (IOSByteArray *) cast_chk([derEncodings elementAtWithInt:i], [IOSByteArray class]);
    LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque24WithByteArray_withJavaIoOutputStream_(derEncoding, output);
  }
}

+ (LibOrgBouncycastleCryptoTlsCertificate *)parseWithJavaIoInputStream:(JavaIoInputStream *)input {
  return LibOrgBouncycastleCryptoTlsCertificate_parseWithJavaIoInputStream_(input);
}

- (IOSObjectArray *)cloneCertificateList {
  IOSObjectArray *result = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(certificateList_))->size_ type:LibOrgBouncycastleAsn1X509X509Certificate_class_()];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(certificateList_, 0, result, 0, result->size_);
  return result;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1X509X509Certificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509X509Certificate;", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, 5, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsCertificate;", 0x9, 6, 7, 5, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1X509X509Certificate;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1X509X509CertificateArray:);
  methods[1].selector = @selector(getCertificateList);
  methods[2].selector = @selector(getCertificateAtWithInt:);
  methods[3].selector = @selector(getLength);
  methods[4].selector = @selector(isEmpty);
  methods[5].selector = @selector(encodeWithJavaIoOutputStream:);
  methods[6].selector = @selector(parseWithJavaIoInputStream:);
  methods[7].selector = @selector(cloneCertificateList);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "EMPTY_CHAIN", "LLibOrgBouncycastleCryptoTlsCertificate;", .constantValue.asLong = 0, 0x19, -1, 8, -1, -1 },
    { "certificateList_", "[LLibOrgBouncycastleAsn1X509X509Certificate;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[LLibOrgBouncycastleAsn1X509X509Certificate;", "getCertificateAt", "I", "encode", "LJavaIoOutputStream;", "LJavaIoIOException;", "parse", "LJavaIoInputStream;", &LibOrgBouncycastleCryptoTlsCertificate_EMPTY_CHAIN };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsCertificate = { "Certificate", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 8, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsCertificate;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoTlsCertificate class]) {
    LibOrgBouncycastleCryptoTlsCertificate_EMPTY_CHAIN = new_LibOrgBouncycastleCryptoTlsCertificate_initWithLibOrgBouncycastleAsn1X509X509CertificateArray_([IOSObjectArray newArrayWithLength:0 type:LibOrgBouncycastleAsn1X509X509Certificate_class_()]);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoTlsCertificate)
  }
}

@end

void LibOrgBouncycastleCryptoTlsCertificate_initWithLibOrgBouncycastleAsn1X509X509CertificateArray_(LibOrgBouncycastleCryptoTlsCertificate *self, IOSObjectArray *certificateList) {
  NSObject_init(self);
  if (certificateList == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'certificateList' cannot be null");
  }
  self->certificateList_ = certificateList;
}

LibOrgBouncycastleCryptoTlsCertificate *new_LibOrgBouncycastleCryptoTlsCertificate_initWithLibOrgBouncycastleAsn1X509X509CertificateArray_(IOSObjectArray *certificateList) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsCertificate, initWithLibOrgBouncycastleAsn1X509X509CertificateArray_, certificateList)
}

LibOrgBouncycastleCryptoTlsCertificate *create_LibOrgBouncycastleCryptoTlsCertificate_initWithLibOrgBouncycastleAsn1X509X509CertificateArray_(IOSObjectArray *certificateList) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsCertificate, initWithLibOrgBouncycastleAsn1X509X509CertificateArray_, certificateList)
}

LibOrgBouncycastleCryptoTlsCertificate *LibOrgBouncycastleCryptoTlsCertificate_parseWithJavaIoInputStream_(JavaIoInputStream *input) {
  LibOrgBouncycastleCryptoTlsCertificate_initialize();
  jint totalLength = LibOrgBouncycastleCryptoTlsTlsUtils_readUint24WithJavaIoInputStream_(input);
  if (totalLength == 0) {
    return LibOrgBouncycastleCryptoTlsCertificate_EMPTY_CHAIN;
  }
  IOSByteArray *certListData = LibOrgBouncycastleCryptoTlsTlsUtils_readFullyWithInt_withJavaIoInputStream_(totalLength, input);
  JavaIoByteArrayInputStream *buf = new_JavaIoByteArrayInputStream_initWithByteArray_(certListData);
  JavaUtilVector *certificate_list = new_JavaUtilVector_init();
  while ([buf available] > 0) {
    IOSByteArray *berEncoding = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque24WithJavaIoInputStream_(buf);
    LibOrgBouncycastleAsn1ASN1Primitive *asn1Cert = LibOrgBouncycastleCryptoTlsTlsUtils_readASN1ObjectWithByteArray_(berEncoding);
    [certificate_list addElementWithId:LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithId_(asn1Cert)];
  }
  IOSObjectArray *certificateList = [IOSObjectArray newArrayWithLength:[certificate_list size] type:LibOrgBouncycastleAsn1X509X509Certificate_class_()];
  for (jint i = 0; i < [certificate_list size]; i++) {
    (void) IOSObjectArray_Set(certificateList, i, (LibOrgBouncycastleAsn1X509X509Certificate *) cast_chk([certificate_list elementAtWithInt:i], [LibOrgBouncycastleAsn1X509X509Certificate class]));
  }
  return new_LibOrgBouncycastleCryptoTlsCertificate_initWithLibOrgBouncycastleAsn1X509X509CertificateArray_(certificateList);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsCertificate)
