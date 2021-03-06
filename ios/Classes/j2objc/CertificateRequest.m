//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/CertificateRequest.java
//

#include "ASN1Encoding.h"
#include "ASN1Primitive.h"
#include "CertificateRequest.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "TlsContext.h"
#include "TlsUtils.h"
#include "X500Name.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/util/Vector.h"

@implementation LibOrgBouncycastleCryptoTlsCertificateRequest

- (instancetype)initWithShortArray:(IOSShortArray *)certificateTypes
                withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
                withJavaUtilVector:(JavaUtilVector *)certificateAuthorities {
  LibOrgBouncycastleCryptoTlsCertificateRequest_initWithShortArray_withJavaUtilVector_withJavaUtilVector_(self, certificateTypes, supportedSignatureAlgorithms, certificateAuthorities);
  return self;
}

- (IOSShortArray *)getCertificateTypes {
  return certificateTypes_;
}

- (JavaUtilVector *)getSupportedSignatureAlgorithms {
  return supportedSignatureAlgorithms_;
}

- (JavaUtilVector *)getCertificateAuthorities {
  return certificateAuthorities_;
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  if (certificateTypes_ == nil || certificateTypes_->size_ == 0) {
    LibOrgBouncycastleCryptoTlsTlsUtils_writeUint8WithInt_withJavaIoOutputStream_(0, output);
  }
  else {
    LibOrgBouncycastleCryptoTlsTlsUtils_writeUint8ArrayWithUint8LengthWithShortArray_withJavaIoOutputStream_(certificateTypes_, output);
  }
  if (supportedSignatureAlgorithms_ != nil) {
    LibOrgBouncycastleCryptoTlsTlsUtils_encodeSupportedSignatureAlgorithmsWithJavaUtilVector_withBoolean_withJavaIoOutputStream_(supportedSignatureAlgorithms_, false, output);
  }
  if (certificateAuthorities_ == nil || [certificateAuthorities_ isEmpty]) {
    LibOrgBouncycastleCryptoTlsTlsUtils_writeUint16WithInt_withJavaIoOutputStream_(0, output);
  }
  else {
    JavaUtilVector *derEncodings = new_JavaUtilVector_initWithInt_([certificateAuthorities_ size]);
    jint totalLength = 0;
    for (jint i = 0; i < [((JavaUtilVector *) nil_chk(certificateAuthorities_)) size]; ++i) {
      LibOrgBouncycastleAsn1X500X500Name *certificateAuthority = (LibOrgBouncycastleAsn1X500X500Name *) cast_chk([((JavaUtilVector *) nil_chk(certificateAuthorities_)) elementAtWithInt:i], [LibOrgBouncycastleAsn1X500X500Name class]);
      IOSByteArray *derEncoding = [((LibOrgBouncycastleAsn1X500X500Name *) nil_chk(certificateAuthority)) getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
      [derEncodings addElementWithId:derEncoding];
      totalLength += ((IOSByteArray *) nil_chk(derEncoding))->size_ + 2;
    }
    LibOrgBouncycastleCryptoTlsTlsUtils_checkUint16WithInt_(totalLength);
    LibOrgBouncycastleCryptoTlsTlsUtils_writeUint16WithInt_withJavaIoOutputStream_(totalLength, output);
    for (jint i = 0; i < [derEncodings size]; ++i) {
      IOSByteArray *derEncoding = (IOSByteArray *) cast_chk([derEncodings elementAtWithInt:i], [IOSByteArray class]);
      LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque16WithByteArray_withJavaIoOutputStream_(derEncoding, output);
    }
  }
}

+ (LibOrgBouncycastleCryptoTlsCertificateRequest *)parseWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                                            withJavaIoInputStream:(JavaIoInputStream *)input {
  return LibOrgBouncycastleCryptoTlsCertificateRequest_parseWithLibOrgBouncycastleCryptoTlsTlsContext_withJavaIoInputStream_(context, input);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "[S", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilVector;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilVector;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsCertificateRequest;", 0x9, 4, 5, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithShortArray:withJavaUtilVector:withJavaUtilVector:);
  methods[1].selector = @selector(getCertificateTypes);
  methods[2].selector = @selector(getSupportedSignatureAlgorithms);
  methods[3].selector = @selector(getCertificateAuthorities);
  methods[4].selector = @selector(encodeWithJavaIoOutputStream:);
  methods[5].selector = @selector(parseWithLibOrgBouncycastleCryptoTlsTlsContext:withJavaIoInputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "certificateTypes_", "[S", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "supportedSignatureAlgorithms_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "certificateAuthorities_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[SLJavaUtilVector;LJavaUtilVector;", "encode", "LJavaIoOutputStream;", "LJavaIoIOException;", "parse", "LLibOrgBouncycastleCryptoTlsTlsContext;LJavaIoInputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsCertificateRequest = { "CertificateRequest", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 6, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsCertificateRequest;
}

@end

void LibOrgBouncycastleCryptoTlsCertificateRequest_initWithShortArray_withJavaUtilVector_withJavaUtilVector_(LibOrgBouncycastleCryptoTlsCertificateRequest *self, IOSShortArray *certificateTypes, JavaUtilVector *supportedSignatureAlgorithms, JavaUtilVector *certificateAuthorities) {
  NSObject_init(self);
  self->certificateTypes_ = certificateTypes;
  self->supportedSignatureAlgorithms_ = supportedSignatureAlgorithms;
  self->certificateAuthorities_ = certificateAuthorities;
}

LibOrgBouncycastleCryptoTlsCertificateRequest *new_LibOrgBouncycastleCryptoTlsCertificateRequest_initWithShortArray_withJavaUtilVector_withJavaUtilVector_(IOSShortArray *certificateTypes, JavaUtilVector *supportedSignatureAlgorithms, JavaUtilVector *certificateAuthorities) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsCertificateRequest, initWithShortArray_withJavaUtilVector_withJavaUtilVector_, certificateTypes, supportedSignatureAlgorithms, certificateAuthorities)
}

LibOrgBouncycastleCryptoTlsCertificateRequest *create_LibOrgBouncycastleCryptoTlsCertificateRequest_initWithShortArray_withJavaUtilVector_withJavaUtilVector_(IOSShortArray *certificateTypes, JavaUtilVector *supportedSignatureAlgorithms, JavaUtilVector *certificateAuthorities) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsCertificateRequest, initWithShortArray_withJavaUtilVector_withJavaUtilVector_, certificateTypes, supportedSignatureAlgorithms, certificateAuthorities)
}

LibOrgBouncycastleCryptoTlsCertificateRequest *LibOrgBouncycastleCryptoTlsCertificateRequest_parseWithLibOrgBouncycastleCryptoTlsTlsContext_withJavaIoInputStream_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, JavaIoInputStream *input) {
  LibOrgBouncycastleCryptoTlsCertificateRequest_initialize();
  jint numTypes = LibOrgBouncycastleCryptoTlsTlsUtils_readUint8WithJavaIoInputStream_(input);
  IOSShortArray *certificateTypes = [IOSShortArray newArrayWithLength:numTypes];
  for (jint i = 0; i < numTypes; ++i) {
    *IOSShortArray_GetRef(certificateTypes, i) = LibOrgBouncycastleCryptoTlsTlsUtils_readUint8WithJavaIoInputStream_(input);
  }
  JavaUtilVector *supportedSignatureAlgorithms = nil;
  if (LibOrgBouncycastleCryptoTlsTlsUtils_isTLSv12WithLibOrgBouncycastleCryptoTlsTlsContext_(context)) {
    supportedSignatureAlgorithms = LibOrgBouncycastleCryptoTlsTlsUtils_parseSupportedSignatureAlgorithmsWithBoolean_withJavaIoInputStream_(false, input);
  }
  JavaUtilVector *certificateAuthorities = new_JavaUtilVector_init();
  IOSByteArray *certAuthData = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque16WithJavaIoInputStream_(input);
  JavaIoByteArrayInputStream *bis = new_JavaIoByteArrayInputStream_initWithByteArray_(certAuthData);
  while ([bis available] > 0) {
    IOSByteArray *derEncoding = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque16WithJavaIoInputStream_(bis);
    LibOrgBouncycastleAsn1ASN1Primitive *asn1 = LibOrgBouncycastleCryptoTlsTlsUtils_readDERObjectWithByteArray_(derEncoding);
    [certificateAuthorities addElementWithId:LibOrgBouncycastleAsn1X500X500Name_getInstanceWithId_(asn1)];
  }
  return new_LibOrgBouncycastleCryptoTlsCertificateRequest_initWithShortArray_withJavaUtilVector_withJavaUtilVector_(certificateTypes, supportedSignatureAlgorithms, certificateAuthorities);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsCertificateRequest)
