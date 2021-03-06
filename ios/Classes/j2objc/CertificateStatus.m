//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/CertificateStatus.java
//

#include "ASN1Encoding.h"
#include "ASN1Primitive.h"
#include "AlertDescription.h"
#include "CertificateStatus.h"
#include "CertificateStatusType.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "OCSPResponse.h"
#include "TlsFatalAlert.h"
#include "TlsUtils.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"

@implementation LibOrgBouncycastleCryptoTlsCertificateStatus

- (instancetype)initWithShort:(jshort)statusType
                       withId:(id)response {
  LibOrgBouncycastleCryptoTlsCertificateStatus_initWithShort_withId_(self, statusType, response);
  return self;
}

- (jshort)getStatusType {
  return statusType_;
}

- (id)getResponse {
  return response_;
}

- (LibOrgBouncycastleAsn1OcspOCSPResponse *)getOCSPResponse {
  if (!LibOrgBouncycastleCryptoTlsCertificateStatus_isCorrectTypeWithShort_withId_(LibOrgBouncycastleCryptoTlsCertificateStatusType_ocsp, response_)) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"'response' is not an OCSPResponse");
  }
  return (LibOrgBouncycastleAsn1OcspOCSPResponse *) cast_chk(response_, [LibOrgBouncycastleAsn1OcspOCSPResponse class]);
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  LibOrgBouncycastleCryptoTlsTlsUtils_writeUint8WithShort_withJavaIoOutputStream_(statusType_, output);
  {
    IOSByteArray *derEncoding;
    switch (statusType_) {
      case LibOrgBouncycastleCryptoTlsCertificateStatusType_ocsp:
      derEncoding = [((LibOrgBouncycastleAsn1OcspOCSPResponse *) nil_chk(((LibOrgBouncycastleAsn1OcspOCSPResponse *) cast_chk(response_, [LibOrgBouncycastleAsn1OcspOCSPResponse class])))) getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
      LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque24WithByteArray_withJavaIoOutputStream_(derEncoding, output);
      break;
      default:
      @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
    }
  }
}

+ (LibOrgBouncycastleCryptoTlsCertificateStatus *)parseWithJavaIoInputStream:(JavaIoInputStream *)input {
  return LibOrgBouncycastleCryptoTlsCertificateStatus_parseWithJavaIoInputStream_(input);
}

+ (jboolean)isCorrectTypeWithShort:(jshort)statusType
                            withId:(id)response {
  return LibOrgBouncycastleCryptoTlsCertificateStatus_isCorrectTypeWithShort_withId_(statusType, response);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "S", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1OcspOCSPResponse;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsCertificateStatus;", 0x9, 4, 5, 3, -1, -1, -1 },
    { NULL, "Z", 0xc, 6, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithShort:withId:);
  methods[1].selector = @selector(getStatusType);
  methods[2].selector = @selector(getResponse);
  methods[3].selector = @selector(getOCSPResponse);
  methods[4].selector = @selector(encodeWithJavaIoOutputStream:);
  methods[5].selector = @selector(parseWithJavaIoInputStream:);
  methods[6].selector = @selector(isCorrectTypeWithShort:withId:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "statusType_", "S", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "response_", "LNSObject;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "SLNSObject;", "encode", "LJavaIoOutputStream;", "LJavaIoIOException;", "parse", "LJavaIoInputStream;", "isCorrectType" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsCertificateStatus = { "CertificateStatus", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsCertificateStatus;
}

@end

void LibOrgBouncycastleCryptoTlsCertificateStatus_initWithShort_withId_(LibOrgBouncycastleCryptoTlsCertificateStatus *self, jshort statusType, id response) {
  NSObject_init(self);
  if (!LibOrgBouncycastleCryptoTlsCertificateStatus_isCorrectTypeWithShort_withId_(statusType, response)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'response' is not an instance of the correct type");
  }
  self->statusType_ = statusType;
  self->response_ = response;
}

LibOrgBouncycastleCryptoTlsCertificateStatus *new_LibOrgBouncycastleCryptoTlsCertificateStatus_initWithShort_withId_(jshort statusType, id response) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsCertificateStatus, initWithShort_withId_, statusType, response)
}

LibOrgBouncycastleCryptoTlsCertificateStatus *create_LibOrgBouncycastleCryptoTlsCertificateStatus_initWithShort_withId_(jshort statusType, id response) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsCertificateStatus, initWithShort_withId_, statusType, response)
}

LibOrgBouncycastleCryptoTlsCertificateStatus *LibOrgBouncycastleCryptoTlsCertificateStatus_parseWithJavaIoInputStream_(JavaIoInputStream *input) {
  LibOrgBouncycastleCryptoTlsCertificateStatus_initialize();
  jshort status_type = LibOrgBouncycastleCryptoTlsTlsUtils_readUint8WithJavaIoInputStream_(input);
  id response;
  switch (status_type) {
    case LibOrgBouncycastleCryptoTlsCertificateStatusType_ocsp:
    {
      IOSByteArray *derEncoding = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque24WithJavaIoInputStream_(input);
      response = LibOrgBouncycastleAsn1OcspOCSPResponse_getInstanceWithId_(LibOrgBouncycastleCryptoTlsTlsUtils_readDERObjectWithByteArray_(derEncoding));
      break;
    }
    default:
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_decode_error);
  }
  return new_LibOrgBouncycastleCryptoTlsCertificateStatus_initWithShort_withId_(status_type, response);
}

jboolean LibOrgBouncycastleCryptoTlsCertificateStatus_isCorrectTypeWithShort_withId_(jshort statusType, id response) {
  LibOrgBouncycastleCryptoTlsCertificateStatus_initialize();
  switch (statusType) {
    case LibOrgBouncycastleCryptoTlsCertificateStatusType_ocsp:
    return [response isKindOfClass:[LibOrgBouncycastleAsn1OcspOCSPResponse class]];
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'statusType' is an unsupported CertificateStatusType");
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsCertificateStatus)
