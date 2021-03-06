//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/AbstractTlsClient.java
//

#ifndef AbstractTlsClient_H
#define AbstractTlsClient_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AbstractTlsPeer.h"
#include "J2ObjC_header.h"
#include "TlsClient.h"

@class IOSByteArray;
@class IOSIntArray;
@class IOSShortArray;
@class JavaLangInteger;
@class JavaUtilHashtable;
@class JavaUtilVector;
@class LibOrgBouncycastleCryptoTlsNewSessionTicket;
@class LibOrgBouncycastleCryptoTlsProtocolVersion;
@protocol LibOrgBouncycastleCryptoTlsTlsCipher;
@protocol LibOrgBouncycastleCryptoTlsTlsCipherFactory;
@protocol LibOrgBouncycastleCryptoTlsTlsClientContext;
@protocol LibOrgBouncycastleCryptoTlsTlsCompression;
@protocol LibOrgBouncycastleCryptoTlsTlsSession;

@interface LibOrgBouncycastleCryptoTlsAbstractTlsClient : LibOrgBouncycastleCryptoTlsAbstractTlsPeer < LibOrgBouncycastleCryptoTlsTlsClient > {
 @public
  id<LibOrgBouncycastleCryptoTlsTlsCipherFactory> cipherFactory_;
  id<LibOrgBouncycastleCryptoTlsTlsClientContext> context_;
  JavaUtilVector *supportedSignatureAlgorithms_;
  IOSIntArray *namedCurves_;
  IOSShortArray *clientECPointFormats_;
  IOSShortArray *serverECPointFormats_;
  jint selectedCipherSuite_;
  jshort selectedCompressionMethod_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory:(id<LibOrgBouncycastleCryptoTlsTlsCipherFactory>)cipherFactory;

- (id<LibOrgBouncycastleCryptoTlsTlsCipher>)getCipher;

- (JavaUtilHashtable *)getClientExtensions;

- (LibOrgBouncycastleCryptoTlsProtocolVersion *)getClientHelloRecordLayerVersion;

- (JavaUtilVector *)getClientSupplementalData;

- (LibOrgBouncycastleCryptoTlsProtocolVersion *)getClientVersion;

- (id<LibOrgBouncycastleCryptoTlsTlsCompression>)getCompression;

- (IOSShortArray *)getCompressionMethods;

- (LibOrgBouncycastleCryptoTlsProtocolVersion *)getMinimumVersion;

- (id<LibOrgBouncycastleCryptoTlsTlsSession>)getSessionToResume;

- (void)init__WithLibOrgBouncycastleCryptoTlsTlsClientContext:(id<LibOrgBouncycastleCryptoTlsTlsClientContext>)context OBJC_METHOD_FAMILY_NONE;

- (jboolean)isFallback;

- (void)notifyNewSessionTicketWithLibOrgBouncycastleCryptoTlsNewSessionTicket:(LibOrgBouncycastleCryptoTlsNewSessionTicket *)newSessionTicket;

- (void)notifySelectedCipherSuiteWithInt:(jint)selectedCipherSuite;

- (void)notifySelectedCompressionMethodWithShort:(jshort)selectedCompressionMethod;

- (void)notifyServerVersionWithLibOrgBouncycastleCryptoTlsProtocolVersion:(LibOrgBouncycastleCryptoTlsProtocolVersion *)serverVersion;

- (void)notifySessionIDWithByteArray:(IOSByteArray *)sessionID;

- (void)processServerExtensionsWithJavaUtilHashtable:(JavaUtilHashtable *)serverExtensions;

- (void)processServerSupplementalDataWithJavaUtilVector:(JavaUtilVector *)serverSupplementalData;

#pragma mark Protected

- (jboolean)allowUnexpectedServerExtensionWithJavaLangInteger:(JavaLangInteger *)extensionType
                                                withByteArray:(IOSByteArray *)extensionData;

- (void)checkForUnexpectedServerExtensionWithJavaUtilHashtable:(JavaUtilHashtable *)serverExtensions
                                           withJavaLangInteger:(JavaLangInteger *)extensionType;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsAbstractTlsClient)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsClient, cipherFactory_, id<LibOrgBouncycastleCryptoTlsTlsCipherFactory>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsClient, context_, id<LibOrgBouncycastleCryptoTlsTlsClientContext>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsClient, supportedSignatureAlgorithms_, JavaUtilVector *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsClient, namedCurves_, IOSIntArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsClient, clientECPointFormats_, IOSShortArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsClient, serverECPointFormats_, IOSShortArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsAbstractTlsClient_init(LibOrgBouncycastleCryptoTlsAbstractTlsClient *self);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsAbstractTlsClient_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_(LibOrgBouncycastleCryptoTlsAbstractTlsClient *self, id<LibOrgBouncycastleCryptoTlsTlsCipherFactory> cipherFactory);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsAbstractTlsClient)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // AbstractTlsClient_H
