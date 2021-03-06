//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/gpg/keybox/CertificateBlob.java
//

#include "Blob.h"
#include "BlobType.h"
#include "BlobVerifier.h"
#include "CertificateBlob.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyBlob.h"
#include "KeyBoxByteBuffer.h"
#include "KeyInformation.h"
#include "UserID.h"
#include "java/lang/Long.h"
#include "java/util/ArrayList.h"
#include "java/util/List.h"

@interface LibOrgBouncycastleGpgKeyboxCertificateBlob ()

- (instancetype)initWithInt:(jint)base
                   withLong:(jlong)length
withLibOrgBouncycastleGpgKeyboxBlobType:(LibOrgBouncycastleGpgKeyboxBlobType *)type
                    withInt:(jint)version_
                    withInt:(jint)blobFlags
                    withInt:(jint)keyNumber
           withJavaUtilList:(id<JavaUtilList>)keyInformation
              withByteArray:(IOSByteArray *)serialNumber
                    withInt:(jint)numberOfUserIDs
           withJavaUtilList:(id<JavaUtilList>)userIds
                    withInt:(jint)numberOfSignatures
           withJavaUtilList:(id<JavaUtilList>)expirationTime
                    withInt:(jint)assignedOwnerTrust
                    withInt:(jint)allValidity
                   withLong:(jlong)recheckAfter
                   withLong:(jlong)newestTimestamp
                   withLong:(jlong)blobCreatedAt
              withByteArray:(IOSByteArray *)keyBytes
              withByteArray:(IOSByteArray *)reserveBytes
              withByteArray:(IOSByteArray *)sha1Checksum;

@end

__attribute__((unused)) static void LibOrgBouncycastleGpgKeyboxCertificateBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(LibOrgBouncycastleGpgKeyboxCertificateBlob *self, jint base, jlong length, LibOrgBouncycastleGpgKeyboxBlobType *type, jint version_, jint blobFlags, jint keyNumber, id<JavaUtilList> keyInformation, IOSByteArray *serialNumber, jint numberOfUserIDs, id<JavaUtilList> userIds, jint numberOfSignatures, id<JavaUtilList> expirationTime, jint assignedOwnerTrust, jint allValidity, jlong recheckAfter, jlong newestTimestamp, jlong blobCreatedAt, IOSByteArray *keyBytes, IOSByteArray *reserveBytes, IOSByteArray *sha1Checksum);

__attribute__((unused)) static LibOrgBouncycastleGpgKeyboxCertificateBlob *new_LibOrgBouncycastleGpgKeyboxCertificateBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(jint base, jlong length, LibOrgBouncycastleGpgKeyboxBlobType *type, jint version_, jint blobFlags, jint keyNumber, id<JavaUtilList> keyInformation, IOSByteArray *serialNumber, jint numberOfUserIDs, id<JavaUtilList> userIds, jint numberOfSignatures, id<JavaUtilList> expirationTime, jint assignedOwnerTrust, jint allValidity, jlong recheckAfter, jlong newestTimestamp, jlong blobCreatedAt, IOSByteArray *keyBytes, IOSByteArray *reserveBytes, IOSByteArray *sha1Checksum) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleGpgKeyboxCertificateBlob *create_LibOrgBouncycastleGpgKeyboxCertificateBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(jint base, jlong length, LibOrgBouncycastleGpgKeyboxBlobType *type, jint version_, jint blobFlags, jint keyNumber, id<JavaUtilList> keyInformation, IOSByteArray *serialNumber, jint numberOfUserIDs, id<JavaUtilList> userIds, jint numberOfSignatures, id<JavaUtilList> expirationTime, jint assignedOwnerTrust, jint allValidity, jlong recheckAfter, jlong newestTimestamp, jlong blobCreatedAt, IOSByteArray *keyBytes, IOSByteArray *reserveBytes, IOSByteArray *sha1Checksum);

@implementation LibOrgBouncycastleGpgKeyboxCertificateBlob

- (instancetype)initWithInt:(jint)base
                   withLong:(jlong)length
withLibOrgBouncycastleGpgKeyboxBlobType:(LibOrgBouncycastleGpgKeyboxBlobType *)type
                    withInt:(jint)version_
                    withInt:(jint)blobFlags
                    withInt:(jint)keyNumber
           withJavaUtilList:(id<JavaUtilList>)keyInformation
              withByteArray:(IOSByteArray *)serialNumber
                    withInt:(jint)numberOfUserIDs
           withJavaUtilList:(id<JavaUtilList>)userIds
                    withInt:(jint)numberOfSignatures
           withJavaUtilList:(id<JavaUtilList>)expirationTime
                    withInt:(jint)assignedOwnerTrust
                    withInt:(jint)allValidity
                   withLong:(jlong)recheckAfter
                   withLong:(jlong)newestTimestamp
                   withLong:(jlong)blobCreatedAt
              withByteArray:(IOSByteArray *)keyBytes
              withByteArray:(IOSByteArray *)reserveBytes
              withByteArray:(IOSByteArray *)sha1Checksum {
  LibOrgBouncycastleGpgKeyboxCertificateBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(self, base, length, type, version_, blobFlags, keyNumber, keyInformation, serialNumber, numberOfUserIDs, userIds, numberOfSignatures, expirationTime, assignedOwnerTrust, allValidity, recheckAfter, newestTimestamp, blobCreatedAt, keyBytes, reserveBytes, sha1Checksum);
  return self;
}

+ (LibOrgBouncycastleGpgKeyboxBlob *)parseContentWithInt:(jint)base
                                                withLong:(jlong)length
                 withLibOrgBouncycastleGpgKeyboxBlobType:(LibOrgBouncycastleGpgKeyboxBlobType *)type
                                                 withInt:(jint)version_
         withLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer:(LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *)buffer
             withLibOrgBouncycastleGpgKeyboxBlobVerifier:(id<LibOrgBouncycastleGpgKeyboxBlobVerifier>)blobVerifier {
  return LibOrgBouncycastleGpgKeyboxCertificateBlob_parseContentWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(base, length, type, version_, buffer, blobVerifier);
}

- (IOSByteArray *)getEncodedCertificate {
  return [self getKeyBytes];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, 1, -1, -1 },
    { NULL, "LLibOrgBouncycastleGpgKeyboxBlob;", 0x8, 2, 3, 4, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withLong:withLibOrgBouncycastleGpgKeyboxBlobType:withInt:withInt:withInt:withJavaUtilList:withByteArray:withInt:withJavaUtilList:withInt:withJavaUtilList:withInt:withInt:withLong:withLong:withLong:withByteArray:withByteArray:withByteArray:);
  methods[1].selector = @selector(parseContentWithInt:withLong:withLibOrgBouncycastleGpgKeyboxBlobType:withInt:withLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer:withLibOrgBouncycastleGpgKeyboxBlobVerifier:);
  methods[2].selector = @selector(getEncodedCertificate);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "IJLLibOrgBouncycastleGpgKeyboxBlobType;IIILJavaUtilList;[BILJavaUtilList;ILJavaUtilList;IIJJJ[B[B[B", "(IJLlib/org/bouncycastle/gpg/keybox/BlobType;IIILjava/util/List<Llib/org/bouncycastle/gpg/keybox/KeyInformation;>;[BILjava/util/List<Llib/org/bouncycastle/gpg/keybox/UserID;>;ILjava/util/List<Ljava/lang/Long;>;IIJJJ[B[B[B)V", "parseContent", "IJLLibOrgBouncycastleGpgKeyboxBlobType;ILLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer;LLibOrgBouncycastleGpgKeyboxBlobVerifier;", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleGpgKeyboxCertificateBlob = { "CertificateBlob", "lib.org.bouncycastle.gpg.keybox", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleGpgKeyboxCertificateBlob;
}

@end

void LibOrgBouncycastleGpgKeyboxCertificateBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(LibOrgBouncycastleGpgKeyboxCertificateBlob *self, jint base, jlong length, LibOrgBouncycastleGpgKeyboxBlobType *type, jint version_, jint blobFlags, jint keyNumber, id<JavaUtilList> keyInformation, IOSByteArray *serialNumber, jint numberOfUserIDs, id<JavaUtilList> userIds, jint numberOfSignatures, id<JavaUtilList> expirationTime, jint assignedOwnerTrust, jint allValidity, jlong recheckAfter, jlong newestTimestamp, jlong blobCreatedAt, IOSByteArray *keyBytes, IOSByteArray *reserveBytes, IOSByteArray *sha1Checksum) {
  LibOrgBouncycastleGpgKeyboxKeyBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(self, base, length, type, version_, blobFlags, keyNumber, keyInformation, serialNumber, numberOfUserIDs, userIds, numberOfSignatures, expirationTime, assignedOwnerTrust, allValidity, recheckAfter, newestTimestamp, blobCreatedAt, keyBytes, reserveBytes, sha1Checksum);
}

LibOrgBouncycastleGpgKeyboxCertificateBlob *new_LibOrgBouncycastleGpgKeyboxCertificateBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(jint base, jlong length, LibOrgBouncycastleGpgKeyboxBlobType *type, jint version_, jint blobFlags, jint keyNumber, id<JavaUtilList> keyInformation, IOSByteArray *serialNumber, jint numberOfUserIDs, id<JavaUtilList> userIds, jint numberOfSignatures, id<JavaUtilList> expirationTime, jint assignedOwnerTrust, jint allValidity, jlong recheckAfter, jlong newestTimestamp, jlong blobCreatedAt, IOSByteArray *keyBytes, IOSByteArray *reserveBytes, IOSByteArray *sha1Checksum) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleGpgKeyboxCertificateBlob, initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_, base, length, type, version_, blobFlags, keyNumber, keyInformation, serialNumber, numberOfUserIDs, userIds, numberOfSignatures, expirationTime, assignedOwnerTrust, allValidity, recheckAfter, newestTimestamp, blobCreatedAt, keyBytes, reserveBytes, sha1Checksum)
}

LibOrgBouncycastleGpgKeyboxCertificateBlob *create_LibOrgBouncycastleGpgKeyboxCertificateBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(jint base, jlong length, LibOrgBouncycastleGpgKeyboxBlobType *type, jint version_, jint blobFlags, jint keyNumber, id<JavaUtilList> keyInformation, IOSByteArray *serialNumber, jint numberOfUserIDs, id<JavaUtilList> userIds, jint numberOfSignatures, id<JavaUtilList> expirationTime, jint assignedOwnerTrust, jint allValidity, jlong recheckAfter, jlong newestTimestamp, jlong blobCreatedAt, IOSByteArray *keyBytes, IOSByteArray *reserveBytes, IOSByteArray *sha1Checksum) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleGpgKeyboxCertificateBlob, initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_, base, length, type, version_, blobFlags, keyNumber, keyInformation, serialNumber, numberOfUserIDs, userIds, numberOfSignatures, expirationTime, assignedOwnerTrust, allValidity, recheckAfter, newestTimestamp, blobCreatedAt, keyBytes, reserveBytes, sha1Checksum)
}

LibOrgBouncycastleGpgKeyboxBlob *LibOrgBouncycastleGpgKeyboxCertificateBlob_parseContentWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(jint base, jlong length, LibOrgBouncycastleGpgKeyboxBlobType *type, jint version_, LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *buffer, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier) {
  LibOrgBouncycastleGpgKeyboxCertificateBlob_initialize();
  LibOrgBouncycastleGpgKeyboxKeyBlob_verifyDigestWithInt_withLong_withLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(base, length, buffer, blobVerifier);
  jint blobFlags = [((LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *) nil_chk(buffer)) u16];
  jlong keyBlockOffset = [buffer u32];
  jlong keyBlockLength = [buffer u32];
  jint keyNumber = [buffer u16];
  jint keyInformationStructureSize = [buffer u16];
  id<JavaUtilList> keyInformation = new_JavaUtilArrayList_init();
  for (jint t = keyNumber - 1; t >= 0; t--) {
    [keyInformation addWithId:LibOrgBouncycastleGpgKeyboxKeyInformation_getInstanceWithId_withInt_withInt_(buffer, keyInformationStructureSize, base)];
  }
  jint sizeOfSerialNumber = [buffer u16];
  IOSByteArray *serialNumber = [IOSByteArray newArrayWithLength:sizeOfSerialNumber];
  [buffer bNWithByteArray:serialNumber];
  jint numberOfUserIDs = [buffer u16];
  [buffer u16];
  id<JavaUtilList> userIds = new_JavaUtilArrayList_init();
  for (jint t = numberOfUserIDs - 1; t >= 0; t--) {
    [userIds addWithId:LibOrgBouncycastleGpgKeyboxUserID_getInstanceWithId_withInt_(buffer, base)];
  }
  jint numberOfSignatures = [buffer u16];
  [buffer u16];
  id<JavaUtilList> signatureExpirationTime = new_JavaUtilArrayList_init();
  for (jint t = numberOfSignatures - 1; t >= 0; t--) {
    [signatureExpirationTime addWithId:JavaLangLong_valueOfWithLong_([buffer u32])];
  }
  jint assignedOwnerTrust = [buffer u8];
  jint allValidity = [buffer u8];
  [buffer u16];
  jlong recheckAfter = [buffer u32];
  jlong newestTimestamp = [buffer u32];
  jlong blobCreatedAt = [buffer u32];
  jlong sizeOfReservedSpace = [buffer u32];
  IOSByteArray *reserveData = [IOSByteArray newArrayWithLength:(jint) sizeOfReservedSpace];
  [buffer bNWithByteArray:reserveData];
  IOSByteArray *keyData = [buffer rangeOfWithInt:(jint) (base + keyBlockOffset) withInt:(jint) (base + keyBlockOffset + keyBlockLength)];
  jint dataSize = (jint) (length - ([buffer position] - base) - 20);
  IOSByteArray *data = [IOSByteArray newArrayWithLength:dataSize];
  [buffer bNWithByteArray:data];
  IOSByteArray *sha1Checksum = [buffer rangeOfWithInt:(jint) (base + length - 20) withInt:(jint) (base + length)];
  [buffer bNWithByteArray:sha1Checksum];
  return new_LibOrgBouncycastleGpgKeyboxCertificateBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(base, length, type, version_, blobFlags, keyNumber, keyInformation, serialNumber, numberOfUserIDs, userIds, numberOfSignatures, signatureExpirationTime, assignedOwnerTrust, allValidity, recheckAfter, newestTimestamp, blobCreatedAt, keyData, reserveData, sha1Checksum);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleGpgKeyboxCertificateBlob)
