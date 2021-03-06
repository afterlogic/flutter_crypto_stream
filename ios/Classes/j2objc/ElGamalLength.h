//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/generation/type/length/ElGamalLength.java
//

#ifndef ElGamalLength_H
#define ElGamalLength_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "KeyLength.h"
#include "java/lang/Enum.h"

@class IOSObjectArray;
@class JavaMathBigInteger;

typedef NS_ENUM(NSUInteger, LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_Enum) {
  LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_Enum__1536 = 0,
  LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_Enum__2048 = 1,
  LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_Enum__3072 = 2,
  LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_Enum__4096 = 3,
  LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_Enum__6144 = 4,
  LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_Enum__8192 = 5,
};

@interface LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength : JavaLangEnum < LibComAfterlogicPgpKeyGenerationTypeLengthKeyLength >

@property (readonly, class, nonnull) LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *_1536 NS_SWIFT_NAME(_1536);
@property (readonly, class, nonnull) LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *_2048 NS_SWIFT_NAME(_2048);
@property (readonly, class, nonnull) LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *_3072 NS_SWIFT_NAME(_3072);
@property (readonly, class, nonnull) LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *_4096 NS_SWIFT_NAME(_4096);
@property (readonly, class, nonnull) LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *_6144 NS_SWIFT_NAME(_6144);
@property (readonly, class, nonnull) LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *_8192 NS_SWIFT_NAME(_8192);
+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength * __nonnull)_1536;

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength * __nonnull)_2048;

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength * __nonnull)_3072;

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength * __nonnull)_4096;

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength * __nonnull)_6144;

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength * __nonnull)_8192;

#pragma mark Public

- (JavaMathBigInteger *)getG;

- (jint)getLength;

- (JavaMathBigInteger *)getP;

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *)valueOfWithNSString:(NSString *)name;

+ (IOSObjectArray *)values;

#pragma mark Package-Private

- (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_Enum)toNSEnum;

@end

J2OBJC_STATIC_INIT(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength)

/*! INTERNAL ONLY - Use enum accessors declared below. */
FOUNDATION_EXPORT LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_values_[];

inline LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_get__1536(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _1536)

inline LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_get__2048(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _2048)

inline LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_get__3072(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _3072)

inline LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_get__4096(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _4096)

inline LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_get__6144(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _6144)

inline LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_get__8192(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _8192)

FOUNDATION_EXPORT IOSObjectArray *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_values(void);

FOUNDATION_EXPORT LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_valueOfWithNSString_(NSString *name);

FOUNDATION_EXPORT LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_fromOrdinal(NSUInteger ordinal);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ElGamalLength_H
