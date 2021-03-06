//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/jpake/JPAKEParticipant.java
//

#ifndef JPAKEParticipant_H
#define JPAKEParticipant_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSCharArray;
@class JavaMathBigInteger;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup;
@class LibOrgBouncycastleCryptoAgreementJpakeJPAKERound1Payload;
@class LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload;
@class LibOrgBouncycastleCryptoAgreementJpakeJPAKERound3Payload;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant : NSObject
@property (readonly, class) jint STATE_INITIALIZED NS_SWIFT_NAME(STATE_INITIALIZED);
@property (readonly, class) jint STATE_ROUND_1_CREATED NS_SWIFT_NAME(STATE_ROUND_1_CREATED);
@property (readonly, class) jint STATE_ROUND_1_VALIDATED NS_SWIFT_NAME(STATE_ROUND_1_VALIDATED);
@property (readonly, class) jint STATE_ROUND_2_CREATED NS_SWIFT_NAME(STATE_ROUND_2_CREATED);
@property (readonly, class) jint STATE_ROUND_2_VALIDATED NS_SWIFT_NAME(STATE_ROUND_2_VALIDATED);
@property (readonly, class) jint STATE_KEY_CALCULATED NS_SWIFT_NAME(STATE_KEY_CALCULATED);
@property (readonly, class) jint STATE_ROUND_3_CREATED NS_SWIFT_NAME(STATE_ROUND_3_CREATED);
@property (readonly, class) jint STATE_ROUND_3_VALIDATED NS_SWIFT_NAME(STATE_ROUND_3_VALIDATED);

+ (jint)STATE_INITIALIZED;

+ (jint)STATE_ROUND_1_CREATED;

+ (jint)STATE_ROUND_1_VALIDATED;

+ (jint)STATE_ROUND_2_CREATED;

+ (jint)STATE_ROUND_2_VALIDATED;

+ (jint)STATE_KEY_CALCULATED;

+ (jint)STATE_ROUND_3_CREATED;

+ (jint)STATE_ROUND_3_VALIDATED;

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)participantId
                             withCharArray:(IOSCharArray *)password;

- (instancetype __nonnull)initWithNSString:(NSString *)participantId
                             withCharArray:(IOSCharArray *)password
withLibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup:(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *)group;

- (instancetype __nonnull)initWithNSString:(NSString *)participantId
                             withCharArray:(IOSCharArray *)password
withLibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup:(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *)group
        withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest
              withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (JavaMathBigInteger *)calculateKeyingMaterial;

- (LibOrgBouncycastleCryptoAgreementJpakeJPAKERound1Payload *)createRound1PayloadToSend;

- (LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload *)createRound2PayloadToSend;

- (LibOrgBouncycastleCryptoAgreementJpakeJPAKERound3Payload *)createRound3PayloadToSendWithJavaMathBigInteger:(JavaMathBigInteger *)keyingMaterial;

- (jint)getState;

- (void)validateRound1PayloadReceivedWithLibOrgBouncycastleCryptoAgreementJpakeJPAKERound1Payload:(LibOrgBouncycastleCryptoAgreementJpakeJPAKERound1Payload *)round1PayloadReceived;

- (void)validateRound2PayloadReceivedWithLibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload:(LibOrgBouncycastleCryptoAgreementJpakeJPAKERound2Payload *)round2PayloadReceived;

- (void)validateRound3PayloadReceivedWithLibOrgBouncycastleCryptoAgreementJpakeJPAKERound3Payload:(LibOrgBouncycastleCryptoAgreementJpakeJPAKERound3Payload *)round3PayloadReceived
                                                                           withJavaMathBigInteger:(JavaMathBigInteger *)keyingMaterial;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant)

inline jint LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_get_STATE_INITIALIZED(void);
#define LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_STATE_INITIALIZED 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant, STATE_INITIALIZED, jint)

inline jint LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_get_STATE_ROUND_1_CREATED(void);
#define LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_STATE_ROUND_1_CREATED 10
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant, STATE_ROUND_1_CREATED, jint)

inline jint LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_get_STATE_ROUND_1_VALIDATED(void);
#define LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_STATE_ROUND_1_VALIDATED 20
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant, STATE_ROUND_1_VALIDATED, jint)

inline jint LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_get_STATE_ROUND_2_CREATED(void);
#define LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_STATE_ROUND_2_CREATED 30
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant, STATE_ROUND_2_CREATED, jint)

inline jint LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_get_STATE_ROUND_2_VALIDATED(void);
#define LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_STATE_ROUND_2_VALIDATED 40
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant, STATE_ROUND_2_VALIDATED, jint)

inline jint LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_get_STATE_KEY_CALCULATED(void);
#define LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_STATE_KEY_CALCULATED 50
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant, STATE_KEY_CALCULATED, jint)

inline jint LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_get_STATE_ROUND_3_CREATED(void);
#define LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_STATE_ROUND_3_CREATED 60
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant, STATE_ROUND_3_CREATED, jint)

inline jint LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_get_STATE_ROUND_3_VALIDATED(void);
#define LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_STATE_ROUND_3_VALIDATED 70
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant, STATE_ROUND_3_VALIDATED, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_initWithNSString_withCharArray_(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant *self, NSString *participantId, IOSCharArray *password);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant *new_LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_initWithNSString_withCharArray_(NSString *participantId, IOSCharArray *password) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant *create_LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_initWithNSString_withCharArray_(NSString *participantId, IOSCharArray *password);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_initWithNSString_withCharArray_withLibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant *self, NSString *participantId, IOSCharArray *password, LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *group);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant *new_LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_initWithNSString_withCharArray_withLibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_(NSString *participantId, IOSCharArray *password, LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *group) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant *create_LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_initWithNSString_withCharArray_withLibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_(NSString *participantId, IOSCharArray *password, LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *group);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_initWithNSString_withCharArray_withLibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_withLibOrgBouncycastleCryptoDigest_withJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant *self, NSString *participantId, IOSCharArray *password, LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *group, id<LibOrgBouncycastleCryptoDigest> digest, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant *new_LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_initWithNSString_withCharArray_withLibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_withLibOrgBouncycastleCryptoDigest_withJavaSecuritySecureRandom_(NSString *participantId, IOSCharArray *password, LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *group, id<LibOrgBouncycastleCryptoDigest> digest, JavaSecuritySecureRandom *random) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant *create_LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant_initWithNSString_withCharArray_withLibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup_withLibOrgBouncycastleCryptoDigest_withJavaSecuritySecureRandom_(NSString *participantId, IOSCharArray *password, LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *group, id<LibOrgBouncycastleCryptoDigest> digest, JavaSecuritySecureRandom *random);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoAgreementJpakeJPAKEParticipant)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JPAKEParticipant_H
