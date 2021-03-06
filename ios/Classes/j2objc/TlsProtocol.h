//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsProtocol.java
//

#ifndef TlsProtocol_H
#define TlsProtocol_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/ByteArrayOutputStream.h"

@class IOSByteArray;
@class IOSIntArray;
@class IOSShortArray;
@class JavaIoByteArrayInputStream;
@class JavaIoInputStream;
@class JavaIoOutputStream;
@class JavaLangInteger;
@class JavaLangThrowable;
@class JavaSecuritySecureRandom;
@class JavaUtilHashtable;
@class JavaUtilVector;
@class LibOrgBouncycastleCryptoTlsAbstractTlsContext;
@class LibOrgBouncycastleCryptoTlsByteQueueInputStream;
@class LibOrgBouncycastleCryptoTlsByteQueueOutputStream;
@class LibOrgBouncycastleCryptoTlsCertificate;
@class LibOrgBouncycastleCryptoTlsRecordStream;
@class LibOrgBouncycastleCryptoTlsSecurityParameters;
@class LibOrgBouncycastleCryptoTlsSessionParameters;
@protocol LibOrgBouncycastleCryptoPrngRandomGenerator;
@protocol LibOrgBouncycastleCryptoTlsTlsContext;
@protocol LibOrgBouncycastleCryptoTlsTlsHandshakeHash;
@protocol LibOrgBouncycastleCryptoTlsTlsKeyExchange;
@protocol LibOrgBouncycastleCryptoTlsTlsPeer;
@protocol LibOrgBouncycastleCryptoTlsTlsSession;

@interface LibOrgBouncycastleCryptoTlsTlsProtocol : NSObject {
 @public
  LibOrgBouncycastleCryptoTlsRecordStream *recordStream_;
  JavaSecuritySecureRandom *secureRandom_;
  id<LibOrgBouncycastleCryptoTlsTlsSession> tlsSession_;
  LibOrgBouncycastleCryptoTlsSessionParameters *sessionParameters_;
  LibOrgBouncycastleCryptoTlsSecurityParameters *securityParameters_;
  LibOrgBouncycastleCryptoTlsCertificate *peerCertificate_;
  IOSIntArray *offeredCipherSuites_;
  IOSShortArray *offeredCompressionMethods_;
  JavaUtilHashtable *clientExtensions_;
  JavaUtilHashtable *serverExtensions_;
  jshort connection_state_;
  jboolean resumedSession_;
  jboolean receivedChangeCipherSpec_;
  jboolean secure_renegotiation_;
  jboolean allowCertificateStatus_;
  jboolean expectSessionTicket_;
  jboolean blocking_;
  LibOrgBouncycastleCryptoTlsByteQueueInputStream *inputBuffers_;
  LibOrgBouncycastleCryptoTlsByteQueueOutputStream *outputBuffer_;
}
@property (readonly, class) JavaLangInteger *EXT_RenegotiationInfo NS_SWIFT_NAME(EXT_RenegotiationInfo);
@property (readonly, class) JavaLangInteger *EXT_SessionTicket NS_SWIFT_NAME(EXT_SessionTicket);
@property (readonly, class) jshort CS_START NS_SWIFT_NAME(CS_START);
@property (readonly, class) jshort CS_CLIENT_HELLO NS_SWIFT_NAME(CS_CLIENT_HELLO);
@property (readonly, class) jshort CS_SERVER_HELLO NS_SWIFT_NAME(CS_SERVER_HELLO);
@property (readonly, class) jshort CS_SERVER_SUPPLEMENTAL_DATA NS_SWIFT_NAME(CS_SERVER_SUPPLEMENTAL_DATA);
@property (readonly, class) jshort CS_SERVER_CERTIFICATE NS_SWIFT_NAME(CS_SERVER_CERTIFICATE);
@property (readonly, class) jshort CS_CERTIFICATE_STATUS NS_SWIFT_NAME(CS_CERTIFICATE_STATUS);
@property (readonly, class) jshort CS_SERVER_KEY_EXCHANGE NS_SWIFT_NAME(CS_SERVER_KEY_EXCHANGE);
@property (readonly, class) jshort CS_CERTIFICATE_REQUEST NS_SWIFT_NAME(CS_CERTIFICATE_REQUEST);
@property (readonly, class) jshort CS_SERVER_HELLO_DONE NS_SWIFT_NAME(CS_SERVER_HELLO_DONE);
@property (readonly, class) jshort CS_CLIENT_SUPPLEMENTAL_DATA NS_SWIFT_NAME(CS_CLIENT_SUPPLEMENTAL_DATA);
@property (readonly, class) jshort CS_CLIENT_CERTIFICATE NS_SWIFT_NAME(CS_CLIENT_CERTIFICATE);
@property (readonly, class) jshort CS_CLIENT_KEY_EXCHANGE NS_SWIFT_NAME(CS_CLIENT_KEY_EXCHANGE);
@property (readonly, class) jshort CS_CERTIFICATE_VERIFY NS_SWIFT_NAME(CS_CERTIFICATE_VERIFY);
@property (readonly, class) jshort CS_CLIENT_FINISHED NS_SWIFT_NAME(CS_CLIENT_FINISHED);
@property (readonly, class) jshort CS_SERVER_SESSION_TICKET NS_SWIFT_NAME(CS_SERVER_SESSION_TICKET);
@property (readonly, class) jshort CS_SERVER_FINISHED NS_SWIFT_NAME(CS_SERVER_FINISHED);
@property (readonly, class) jshort CS_END NS_SWIFT_NAME(CS_END);
@property (readonly, class) jshort ADS_MODE_1_Nsub1 NS_SWIFT_NAME(ADS_MODE_1_Nsub1);
@property (readonly, class) jshort ADS_MODE_0_N NS_SWIFT_NAME(ADS_MODE_0_N);
@property (readonly, class) jshort ADS_MODE_0_N_FIRSTONLY NS_SWIFT_NAME(ADS_MODE_0_N_FIRSTONLY);

+ (JavaLangInteger *)EXT_RenegotiationInfo;

+ (JavaLangInteger *)EXT_SessionTicket;

+ (jshort)CS_START;

+ (jshort)CS_CLIENT_HELLO;

+ (jshort)CS_SERVER_HELLO;

+ (jshort)CS_SERVER_SUPPLEMENTAL_DATA;

+ (jshort)CS_SERVER_CERTIFICATE;

+ (jshort)CS_CERTIFICATE_STATUS;

+ (jshort)CS_SERVER_KEY_EXCHANGE;

+ (jshort)CS_CERTIFICATE_REQUEST;

+ (jshort)CS_SERVER_HELLO_DONE;

+ (jshort)CS_CLIENT_SUPPLEMENTAL_DATA;

+ (jshort)CS_CLIENT_CERTIFICATE;

+ (jshort)CS_CLIENT_KEY_EXCHANGE;

+ (jshort)CS_CERTIFICATE_VERIFY;

+ (jshort)CS_CLIENT_FINISHED;

+ (jshort)CS_SERVER_SESSION_TICKET;

+ (jshort)CS_SERVER_FINISHED;

+ (jshort)CS_END;

+ (jshort)ADS_MODE_1_Nsub1;

+ (jshort)ADS_MODE_0_N;

+ (jshort)ADS_MODE_0_N_FIRSTONLY;

#pragma mark Public

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)input
                             withJavaIoOutputStream:(JavaIoOutputStream *)output
                       withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom;

- (void)close;

- (void)closeInput;

- (jint)getAvailableInputBytes;

- (jint)getAvailableOutputBytes;

- (JavaIoInputStream *)getInputStream;

- (JavaIoOutputStream *)getOutputStream;

- (jboolean)isClosed;

- (void)offerInputWithByteArray:(IOSByteArray *)input;

- (void)offerOutputWithByteArray:(IOSByteArray *)buffer
                         withInt:(jint)offset
                         withInt:(jint)length;

- (jint)readInputWithByteArray:(IOSByteArray *)buffer
                       withInt:(jint)offset
                       withInt:(jint)length;

- (jint)readOutputWithByteArray:(IOSByteArray *)buffer
                        withInt:(jint)offset
                        withInt:(jint)length;

#pragma mark Protected

- (jint)applicationDataAvailable;

- (void)applyMaxFragmentLengthExtension;

+ (void)assertEmptyWithJavaIoByteArrayInputStream:(JavaIoByteArrayInputStream *)buf;

- (void)blockForHandshake;

- (void)checkReceivedChangeCipherSpecWithBoolean:(jboolean)expected;

- (void)cleanupHandshake;

- (void)completeHandshake;

+ (IOSByteArray *)createRandomBlockWithBoolean:(jboolean)useGMTUnixTime
withLibOrgBouncycastleCryptoPrngRandomGenerator:(id<LibOrgBouncycastleCryptoPrngRandomGenerator>)randomGenerator;

+ (IOSByteArray *)createRenegotiationInfoWithByteArray:(IOSByteArray *)renegotiated_connection;

- (IOSByteArray *)createVerifyDataWithBoolean:(jboolean)isServer;

+ (void)establishMasterSecretWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                         withLibOrgBouncycastleCryptoTlsTlsKeyExchange:(id<LibOrgBouncycastleCryptoTlsTlsKeyExchange>)keyExchange;

- (void)flush;

- (id<LibOrgBouncycastleCryptoTlsTlsContext>)getContext;

+ (IOSByteArray *)getCurrentPRFHashWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                             withLibOrgBouncycastleCryptoTlsTlsHandshakeHash:(id<LibOrgBouncycastleCryptoTlsTlsHandshakeHash>)handshakeHash
                                                               withByteArray:(IOSByteArray *)sslSender;

- (id<LibOrgBouncycastleCryptoTlsTlsPeer>)getPeer;

+ (jint)getPRFAlgorithmWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                                         withInt:(jint)ciphersuite;

- (void)handleAlertMessageWithShort:(jshort)alertLevel
                          withShort:(jshort)alertDescription;

- (void)handleAlertWarningMessageWithShort:(jshort)alertDescription;

- (void)handleChangeCipherSpecMessage;

- (void)handleCloseWithBoolean:(jboolean)user_canceled;

- (void)handleExceptionWithShort:(jshort)alertDescription
                    withNSString:(NSString *)message
           withJavaLangThrowable:(JavaLangThrowable *)cause;

- (void)handleFailure;

- (void)handleHandshakeMessageWithShort:(jshort)type
         withJavaIoByteArrayInputStream:(JavaIoByteArrayInputStream *)buf;

- (void)invalidateSession;

- (void)processFinishedMessageWithJavaIoByteArrayInputStream:(JavaIoByteArrayInputStream *)buf;

- (jshort)processMaxFragmentLengthExtensionWithJavaUtilHashtable:(JavaUtilHashtable *)clientExtensions
                                           withJavaUtilHashtable:(JavaUtilHashtable *)serverExtensions
                                                       withShort:(jshort)alertDescription;

- (void)processRecordWithShort:(jshort)protocol
                 withByteArray:(IOSByteArray *)buf
                       withInt:(jint)off
                       withInt:(jint)len;

- (void)raiseAlertFatalWithShort:(jshort)alertDescription
                    withNSString:(NSString *)message
           withJavaLangThrowable:(JavaLangThrowable *)cause;

- (void)raiseAlertWarningWithShort:(jshort)alertDescription
                      withNSString:(NSString *)message;

- (jint)readApplicationDataWithByteArray:(IOSByteArray *)buf
                                 withInt:(jint)offset
                                 withInt:(jint)len;

+ (JavaUtilHashtable *)readExtensionsWithJavaIoByteArrayInputStream:(JavaIoByteArrayInputStream *)input;

+ (JavaUtilVector *)readSupplementalDataMessageWithJavaIoByteArrayInputStream:(JavaIoByteArrayInputStream *)input;

- (void)refuseRenegotiation;

- (void)safeCheckRecordHeaderWithByteArray:(IOSByteArray *)recordHeader;

- (void)safeReadRecord;

- (void)safeWriteRecordWithShort:(jshort)type
                   withByteArray:(IOSByteArray *)buf
                         withInt:(jint)offset
                         withInt:(jint)len;

- (void)sendCertificateMessageWithLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)certificate;

- (void)sendChangeCipherSpecMessage;

- (void)sendFinishedMessage;

- (void)sendSupplementalDataMessageWithJavaUtilVector:(JavaUtilVector *)supplementalData;

- (void)setAppDataSplitModeWithInt:(jint)appDataSplitMode;

- (void)writeDataWithByteArray:(IOSByteArray *)buf
                       withInt:(jint)offset
                       withInt:(jint)len;

+ (void)writeExtensionsWithJavaIoOutputStream:(JavaIoOutputStream *)output
                        withJavaUtilHashtable:(JavaUtilHashtable *)extensions;

- (void)writeHandshakeMessageWithByteArray:(IOSByteArray *)buf
                                   withInt:(jint)off
                                   withInt:(jint)len;

+ (void)writeSelectedExtensionsWithJavaIoOutputStream:(JavaIoOutputStream *)output
                                withJavaUtilHashtable:(JavaUtilHashtable *)extensions
                                          withBoolean:(jboolean)selectEmpty;

+ (void)writeSupplementalDataWithJavaIoOutputStream:(JavaIoOutputStream *)output
                                 withJavaUtilVector:(JavaUtilVector *)supplementalData;

#pragma mark Package-Private

- (LibOrgBouncycastleCryptoTlsAbstractTlsContext *)getContextAdmin;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoTlsTlsProtocol)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, recordStream_, LibOrgBouncycastleCryptoTlsRecordStream *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, secureRandom_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, tlsSession_, id<LibOrgBouncycastleCryptoTlsTlsSession>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, sessionParameters_, LibOrgBouncycastleCryptoTlsSessionParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, securityParameters_, LibOrgBouncycastleCryptoTlsSecurityParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, peerCertificate_, LibOrgBouncycastleCryptoTlsCertificate *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, offeredCipherSuites_, IOSIntArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, offeredCompressionMethods_, IOSShortArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, clientExtensions_, JavaUtilHashtable *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, serverExtensions_, JavaUtilHashtable *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, inputBuffers_, LibOrgBouncycastleCryptoTlsByteQueueInputStream *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsProtocol, outputBuffer_, LibOrgBouncycastleCryptoTlsByteQueueOutputStream *)

inline JavaLangInteger *LibOrgBouncycastleCryptoTlsTlsProtocol_get_EXT_RenegotiationInfo(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaLangInteger *LibOrgBouncycastleCryptoTlsTlsProtocol_EXT_RenegotiationInfo;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoTlsTlsProtocol, EXT_RenegotiationInfo, JavaLangInteger *)

inline JavaLangInteger *LibOrgBouncycastleCryptoTlsTlsProtocol_get_EXT_SessionTicket(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaLangInteger *LibOrgBouncycastleCryptoTlsTlsProtocol_EXT_SessionTicket;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoTlsTlsProtocol, EXT_SessionTicket, JavaLangInteger *)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_START(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_START 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_START, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_CLIENT_HELLO(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_CLIENT_HELLO 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_CLIENT_HELLO, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_SERVER_HELLO(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_SERVER_HELLO 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_SERVER_HELLO, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_SERVER_SUPPLEMENTAL_DATA(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_SERVER_SUPPLEMENTAL_DATA 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_SERVER_SUPPLEMENTAL_DATA, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_SERVER_CERTIFICATE(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_SERVER_CERTIFICATE 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_SERVER_CERTIFICATE, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_CERTIFICATE_STATUS(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_CERTIFICATE_STATUS 5
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_CERTIFICATE_STATUS, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_SERVER_KEY_EXCHANGE(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_SERVER_KEY_EXCHANGE 6
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_SERVER_KEY_EXCHANGE, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_CERTIFICATE_REQUEST(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_CERTIFICATE_REQUEST 7
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_CERTIFICATE_REQUEST, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_SERVER_HELLO_DONE(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_SERVER_HELLO_DONE 8
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_SERVER_HELLO_DONE, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_CLIENT_SUPPLEMENTAL_DATA(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_CLIENT_SUPPLEMENTAL_DATA 9
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_CLIENT_SUPPLEMENTAL_DATA, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_CLIENT_CERTIFICATE(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_CLIENT_CERTIFICATE 10
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_CLIENT_CERTIFICATE, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_CLIENT_KEY_EXCHANGE(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_CLIENT_KEY_EXCHANGE 11
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_CLIENT_KEY_EXCHANGE, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_CERTIFICATE_VERIFY(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_CERTIFICATE_VERIFY 12
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_CERTIFICATE_VERIFY, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_CLIENT_FINISHED(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_CLIENT_FINISHED 13
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_CLIENT_FINISHED, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_SERVER_SESSION_TICKET(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_SERVER_SESSION_TICKET 14
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_SERVER_SESSION_TICKET, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_SERVER_FINISHED(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_SERVER_FINISHED 15
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_SERVER_FINISHED, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_CS_END(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_CS_END 16
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, CS_END, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_ADS_MODE_1_Nsub1(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_ADS_MODE_1_Nsub1 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, ADS_MODE_1_Nsub1, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_ADS_MODE_0_N(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_ADS_MODE_0_N 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, ADS_MODE_0_N, jshort)

inline jshort LibOrgBouncycastleCryptoTlsTlsProtocol_get_ADS_MODE_0_N_FIRSTONLY(void);
#define LibOrgBouncycastleCryptoTlsTlsProtocol_ADS_MODE_0_N_FIRSTONLY 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsTlsProtocol, ADS_MODE_0_N_FIRSTONLY, jshort)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsProtocol_initWithJavaIoInputStream_withJavaIoOutputStream_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoTlsTlsProtocol *self, JavaIoInputStream *input, JavaIoOutputStream *output, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsProtocol_initWithJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoTlsTlsProtocol *self, JavaSecuritySecureRandom *secureRandom);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsProtocol_assertEmptyWithJavaIoByteArrayInputStream_(JavaIoByteArrayInputStream *buf);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoTlsTlsProtocol_createRandomBlockWithBoolean_withLibOrgBouncycastleCryptoPrngRandomGenerator_(jboolean useGMTUnixTime, id<LibOrgBouncycastleCryptoPrngRandomGenerator> randomGenerator);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoTlsTlsProtocol_createRenegotiationInfoWithByteArray_(IOSByteArray *renegotiated_connection);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsProtocol_establishMasterSecretWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsTlsKeyExchange_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, id<LibOrgBouncycastleCryptoTlsTlsKeyExchange> keyExchange);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleCryptoTlsTlsProtocol_getCurrentPRFHashWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsTlsHandshakeHash_withByteArray_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, id<LibOrgBouncycastleCryptoTlsTlsHandshakeHash> handshakeHash, IOSByteArray *sslSender);

FOUNDATION_EXPORT JavaUtilHashtable *LibOrgBouncycastleCryptoTlsTlsProtocol_readExtensionsWithJavaIoByteArrayInputStream_(JavaIoByteArrayInputStream *input);

FOUNDATION_EXPORT JavaUtilVector *LibOrgBouncycastleCryptoTlsTlsProtocol_readSupplementalDataMessageWithJavaIoByteArrayInputStream_(JavaIoByteArrayInputStream *input);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsProtocol_writeExtensionsWithJavaIoOutputStream_withJavaUtilHashtable_(JavaIoOutputStream *output, JavaUtilHashtable *extensions);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsProtocol_writeSelectedExtensionsWithJavaIoOutputStream_withJavaUtilHashtable_withBoolean_(JavaIoOutputStream *output, JavaUtilHashtable *extensions, jboolean selectEmpty);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsProtocol_writeSupplementalDataWithJavaIoOutputStream_withJavaUtilVector_(JavaIoOutputStream *output, JavaUtilVector *supplementalData);

FOUNDATION_EXPORT jint LibOrgBouncycastleCryptoTlsTlsProtocol_getPRFAlgorithmWithLibOrgBouncycastleCryptoTlsTlsContext_withInt_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, jint ciphersuite);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsTlsProtocol)

@interface LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage : JavaIoByteArrayOutputStream

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoTlsTlsProtocol:(LibOrgBouncycastleCryptoTlsTlsProtocol *)outer$
                                                               withShort:(jshort)handshakeType;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoTlsTlsProtocol:(LibOrgBouncycastleCryptoTlsTlsProtocol *)outer$
                                                               withShort:(jshort)handshakeType
                                                                 withInt:(jint)length;

- (void)writeToRecordStream;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithInt:(jint)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage_initWithLibOrgBouncycastleCryptoTlsTlsProtocol_withShort_(LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage *self, LibOrgBouncycastleCryptoTlsTlsProtocol *outer$, jshort handshakeType);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage *new_LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage_initWithLibOrgBouncycastleCryptoTlsTlsProtocol_withShort_(LibOrgBouncycastleCryptoTlsTlsProtocol *outer$, jshort handshakeType) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage *create_LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage_initWithLibOrgBouncycastleCryptoTlsTlsProtocol_withShort_(LibOrgBouncycastleCryptoTlsTlsProtocol *outer$, jshort handshakeType);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage_initWithLibOrgBouncycastleCryptoTlsTlsProtocol_withShort_withInt_(LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage *self, LibOrgBouncycastleCryptoTlsTlsProtocol *outer$, jshort handshakeType, jint length);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage *new_LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage_initWithLibOrgBouncycastleCryptoTlsTlsProtocol_withShort_withInt_(LibOrgBouncycastleCryptoTlsTlsProtocol *outer$, jshort handshakeType, jint length) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage *create_LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage_initWithLibOrgBouncycastleCryptoTlsTlsProtocol_withShort_withInt_(LibOrgBouncycastleCryptoTlsTlsProtocol *outer$, jshort handshakeType, jint length);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsTlsProtocol_HandshakeMessage)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TlsProtocol_H
