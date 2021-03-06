//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/encoders/HexEncoder.java
//

#ifndef HexEncoder_H
#define HexEncoder_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "Encoder.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoOutputStream;

@interface LibOrgBouncycastleUtilEncodersHexEncoder : NSObject < LibOrgBouncycastleUtilEncodersEncoder > {
 @public
  IOSByteArray *encodingTable_;
  IOSByteArray *decodingTable_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (jint)decodeWithByteArray:(IOSByteArray *)data
                    withInt:(jint)off
                    withInt:(jint)length
     withJavaIoOutputStream:(JavaIoOutputStream *)outArg;

- (jint)decodeWithNSString:(NSString *)data
    withJavaIoOutputStream:(JavaIoOutputStream *)outArg;

- (jint)encodeWithByteArray:(IOSByteArray *)data
                    withInt:(jint)off
                    withInt:(jint)length
     withJavaIoOutputStream:(JavaIoOutputStream *)outArg;

#pragma mark Protected

- (void)initialiseDecodingTable OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilEncodersHexEncoder)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleUtilEncodersHexEncoder, encodingTable_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleUtilEncodersHexEncoder, decodingTable_, IOSByteArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilEncodersHexEncoder_init(LibOrgBouncycastleUtilEncodersHexEncoder *self);

FOUNDATION_EXPORT LibOrgBouncycastleUtilEncodersHexEncoder *new_LibOrgBouncycastleUtilEncodersHexEncoder_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilEncodersHexEncoder *create_LibOrgBouncycastleUtilEncodersHexEncoder_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilEncodersHexEncoder)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // HexEncoder_H
