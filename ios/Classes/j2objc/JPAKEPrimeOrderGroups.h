//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/agreement/jpake/JPAKEPrimeOrderGroups.java
//

#ifndef JPAKEPrimeOrderGroups_H
#define JPAKEPrimeOrderGroups_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup;

@interface LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups : NSObject
@property (readonly, class) LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *SUN_JCE_1024 NS_SWIFT_NAME(SUN_JCE_1024);
@property (readonly, class) LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *NIST_2048 NS_SWIFT_NAME(NIST_2048);
@property (readonly, class) LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *NIST_3072 NS_SWIFT_NAME(NIST_3072);

+ (LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *)SUN_JCE_1024;

+ (LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *)NIST_2048;

+ (LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *)NIST_3072;

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups)

inline LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups_get_SUN_JCE_1024(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups_SUN_JCE_1024;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups, SUN_JCE_1024, LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *)

inline LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups_get_NIST_2048(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups_NIST_2048;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups, NIST_2048, LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *)

inline LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups_get_NIST_3072(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups_NIST_3072;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups, NIST_3072, LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroup *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups_init(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups *new_LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups *create_LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoAgreementJpakeJPAKEPrimeOrderGroups)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JPAKEPrimeOrderGroups_H
