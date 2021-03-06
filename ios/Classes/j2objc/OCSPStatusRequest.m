//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/OCSPStatusRequest.java
//

#include "ASN1Encoding.h"
#include "ASN1Primitive.h"
#include "Extensions.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "OCSPStatusRequest.h"
#include "ResponderID.h"
#include "Streams.h"
#include "TlsUtils.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/util/Vector.h"

@implementation LibOrgBouncycastleCryptoTlsOCSPStatusRequest

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)responderIDList
withLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)requestExtensions {
  LibOrgBouncycastleCryptoTlsOCSPStatusRequest_initWithJavaUtilVector_withLibOrgBouncycastleAsn1X509Extensions_(self, responderIDList, requestExtensions);
  return self;
}

- (JavaUtilVector *)getResponderIDList {
  return responderIDList_;
}

- (LibOrgBouncycastleAsn1X509Extensions *)getRequestExtensions {
  return requestExtensions_;
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  if (responderIDList_ == nil || [responderIDList_ isEmpty]) {
    LibOrgBouncycastleCryptoTlsTlsUtils_writeUint16WithInt_withJavaIoOutputStream_(0, output);
  }
  else {
    JavaIoByteArrayOutputStream *buf = new_JavaIoByteArrayOutputStream_init();
    for (jint i = 0; i < [((JavaUtilVector *) nil_chk(responderIDList_)) size]; ++i) {
      LibOrgBouncycastleAsn1OcspResponderID *responderID = (LibOrgBouncycastleAsn1OcspResponderID *) cast_chk([((JavaUtilVector *) nil_chk(responderIDList_)) elementAtWithInt:i], [LibOrgBouncycastleAsn1OcspResponderID class]);
      IOSByteArray *derEncoding = [((LibOrgBouncycastleAsn1OcspResponderID *) nil_chk(responderID)) getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
      LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque16WithByteArray_withJavaIoOutputStream_(derEncoding, buf);
    }
    LibOrgBouncycastleCryptoTlsTlsUtils_checkUint16WithInt_([buf size]);
    LibOrgBouncycastleCryptoTlsTlsUtils_writeUint16WithInt_withJavaIoOutputStream_([buf size], output);
    LibOrgBouncycastleUtilIoStreams_writeBufToWithJavaIoByteArrayOutputStream_withJavaIoOutputStream_(buf, output);
  }
  if (requestExtensions_ == nil) {
    LibOrgBouncycastleCryptoTlsTlsUtils_writeUint16WithInt_withJavaIoOutputStream_(0, output);
  }
  else {
    IOSByteArray *derEncoding = [requestExtensions_ getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
    LibOrgBouncycastleCryptoTlsTlsUtils_checkUint16WithInt_(((IOSByteArray *) nil_chk(derEncoding))->size_);
    LibOrgBouncycastleCryptoTlsTlsUtils_writeUint16WithInt_withJavaIoOutputStream_(derEncoding->size_, output);
    [((JavaIoOutputStream *) nil_chk(output)) writeWithByteArray:derEncoding];
  }
}

+ (LibOrgBouncycastleCryptoTlsOCSPStatusRequest *)parseWithJavaIoInputStream:(JavaIoInputStream *)input {
  return LibOrgBouncycastleCryptoTlsOCSPStatusRequest_parseWithJavaIoInputStream_(input);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaUtilVector;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsOCSPStatusRequest;", 0x9, 4, 5, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaUtilVector:withLibOrgBouncycastleAsn1X509Extensions:);
  methods[1].selector = @selector(getResponderIDList);
  methods[2].selector = @selector(getRequestExtensions);
  methods[3].selector = @selector(encodeWithJavaIoOutputStream:);
  methods[4].selector = @selector(parseWithJavaIoInputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "responderIDList_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "requestExtensions_", "LLibOrgBouncycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaUtilVector;LLibOrgBouncycastleAsn1X509Extensions;", "encode", "LJavaIoOutputStream;", "LJavaIoIOException;", "parse", "LJavaIoInputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsOCSPStatusRequest = { "OCSPStatusRequest", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsOCSPStatusRequest;
}

@end

void LibOrgBouncycastleCryptoTlsOCSPStatusRequest_initWithJavaUtilVector_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleCryptoTlsOCSPStatusRequest *self, JavaUtilVector *responderIDList, LibOrgBouncycastleAsn1X509Extensions *requestExtensions) {
  NSObject_init(self);
  self->responderIDList_ = responderIDList;
  self->requestExtensions_ = requestExtensions;
}

LibOrgBouncycastleCryptoTlsOCSPStatusRequest *new_LibOrgBouncycastleCryptoTlsOCSPStatusRequest_initWithJavaUtilVector_withLibOrgBouncycastleAsn1X509Extensions_(JavaUtilVector *responderIDList, LibOrgBouncycastleAsn1X509Extensions *requestExtensions) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsOCSPStatusRequest, initWithJavaUtilVector_withLibOrgBouncycastleAsn1X509Extensions_, responderIDList, requestExtensions)
}

LibOrgBouncycastleCryptoTlsOCSPStatusRequest *create_LibOrgBouncycastleCryptoTlsOCSPStatusRequest_initWithJavaUtilVector_withLibOrgBouncycastleAsn1X509Extensions_(JavaUtilVector *responderIDList, LibOrgBouncycastleAsn1X509Extensions *requestExtensions) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsOCSPStatusRequest, initWithJavaUtilVector_withLibOrgBouncycastleAsn1X509Extensions_, responderIDList, requestExtensions)
}

LibOrgBouncycastleCryptoTlsOCSPStatusRequest *LibOrgBouncycastleCryptoTlsOCSPStatusRequest_parseWithJavaIoInputStream_(JavaIoInputStream *input) {
  LibOrgBouncycastleCryptoTlsOCSPStatusRequest_initialize();
  JavaUtilVector *responderIDList = new_JavaUtilVector_init();
  {
    jint length = LibOrgBouncycastleCryptoTlsTlsUtils_readUint16WithJavaIoInputStream_(input);
    if (length > 0) {
      IOSByteArray *data = LibOrgBouncycastleCryptoTlsTlsUtils_readFullyWithInt_withJavaIoInputStream_(length, input);
      JavaIoByteArrayInputStream *buf = new_JavaIoByteArrayInputStream_initWithByteArray_(data);
      do {
        IOSByteArray *derEncoding = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque16WithJavaIoInputStream_(buf);
        LibOrgBouncycastleAsn1OcspResponderID *responderID = LibOrgBouncycastleAsn1OcspResponderID_getInstanceWithId_(LibOrgBouncycastleCryptoTlsTlsUtils_readDERObjectWithByteArray_(derEncoding));
        [responderIDList addElementWithId:responderID];
      }
      while ([buf available] > 0);
    }
  }
  LibOrgBouncycastleAsn1X509Extensions *requestExtensions = nil;
  {
    jint length = LibOrgBouncycastleCryptoTlsTlsUtils_readUint16WithJavaIoInputStream_(input);
    if (length > 0) {
      IOSByteArray *derEncoding = LibOrgBouncycastleCryptoTlsTlsUtils_readFullyWithInt_withJavaIoInputStream_(length, input);
      requestExtensions = LibOrgBouncycastleAsn1X509Extensions_getInstanceWithId_(LibOrgBouncycastleCryptoTlsTlsUtils_readDERObjectWithByteArray_(derEncoding));
    }
  }
  return new_LibOrgBouncycastleCryptoTlsOCSPStatusRequest_initWithJavaUtilVector_withLibOrgBouncycastleAsn1X509Extensions_(responderIDList, requestExtensions);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsOCSPStatusRequest)
