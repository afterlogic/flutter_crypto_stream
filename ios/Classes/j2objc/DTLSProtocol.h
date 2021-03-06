//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/DTLSProtocol.java
//

#ifndef DTLSProtocol_H
#define DTLSProtocol_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;
@class JavaUtilHashtable;
@class JavaUtilVector;
@class LibOrgBouncycastleCryptoTlsCertificate;
@class LibOrgBouncycastleCryptoTlsDTLSRecordLayer;

@interface LibOrgBouncycastleCryptoTlsDTLSProtocol : NSObject {
 @public
  JavaSecuritySecureRandom *secureRandom_;
}

#pragma mark Protected

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

+ (void)applyMaxFragmentLengthExtensionWithLibOrgBouncycastleCryptoTlsDTLSRecordLayer:(LibOrgBouncycastleCryptoTlsDTLSRecordLayer *)recordLayer
                                                                            withShort:(jshort)maxFragmentLength;

+ (jshort)evaluateMaxFragmentLengthExtensionWithBoolean:(jboolean)resumedSession
                                  withJavaUtilHashtable:(JavaUtilHashtable *)clientExtensions
                                  withJavaUtilHashtable:(JavaUtilHashtable *)serverExtensions
                                              withShort:(jshort)alertDescription;

+ (IOSByteArray *)generateCertificateWithLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)certificate;

+ (IOSByteArray *)generateSupplementalDataWithJavaUtilVector:(JavaUtilVector *)supplementalData;

- (void)processFinishedWithByteArray:(IOSByteArray *)body
                       withByteArray:(IOSByteArray *)expected_verify_data;

+ (void)validateSelectedCipherSuiteWithInt:(jint)selectedCipherSuite
                                 withShort:(jshort)alertDescription;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsDTLSProtocol)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsDTLSProtocol, secureRandom_, JavaSecuritySecureRandom *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsDTLSProtocol_initWithJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoTlsDTLSProtocol *self, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsDTLSProtocol_applyMaxFragmentLengthExtensionWithLibOrgBouncycastleCryptoTlsDTLSRecordLayer_withShort_(LibOrgBouncycastleCryptoTlsDTLSRecordLayer *recordLayer, jshort maxFragmentLength);

FOUNDATION_EXPORT jshort LibOrgBouncycastleCryptoTlsDTLSProtocol_evaluateMaxFragmentLengthExtensionWithBoolean_withJavaUtilHashtable_withJavaUtilHashtable_withShort_(jboolean resumedSession, JavaUtilHashtable *clientExtensions, JavaUtilHashtable *serverExtensions, jshort alertDescription);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoTlsDTLSProtocol_generateCertificateWithLibOrgBouncycastleCryptoTlsCertificate_(LibOrgBouncycastleCryptoTlsCertificate *certificate);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoTlsDTLSProtocol_generateSupplementalDataWithJavaUtilVector_(JavaUtilVector *supplementalData);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsDTLSProtocol_validateSelectedCipherSuiteWithInt_withShort_(jint selectedCipherSuite, jshort alertDescription);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsDTLSProtocol)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DTLSProtocol_H
