//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsCompression.java
//

#ifndef TlsCompression_H
#define TlsCompression_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaIoOutputStream;

@protocol LibOrgBouncycastleCryptoTlsTlsCompression < JavaObject >

- (JavaIoOutputStream *)compressWithJavaIoOutputStream:(JavaIoOutputStream *)output;

- (JavaIoOutputStream *)decompressWithJavaIoOutputStream:(JavaIoOutputStream *)output;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsTlsCompression)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsTlsCompression)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TlsCompression_H
