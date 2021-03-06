//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/ServerNameList.java
//

#include "AlertDescription.h"
#include "Arrays.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NameType.h"
#include "ServerName.h"
#include "ServerNameList.h"
#include "Streams.h"
#include "TlsFatalAlert.h"
#include "TlsUtils.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Vector.h"

@interface LibOrgBouncycastleCryptoTlsServerNameList ()

+ (IOSShortArray *)checkNameTypeWithShortArray:(IOSShortArray *)nameTypesSeen
                                     withShort:(jshort)nameType;

@end

__attribute__((unused)) static IOSShortArray *LibOrgBouncycastleCryptoTlsServerNameList_checkNameTypeWithShortArray_withShort_(IOSShortArray *nameTypesSeen, jshort nameType);

@implementation LibOrgBouncycastleCryptoTlsServerNameList

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)serverNameList {
  LibOrgBouncycastleCryptoTlsServerNameList_initWithJavaUtilVector_(self, serverNameList);
  return self;
}

- (JavaUtilVector *)getServerNameList {
  return serverNameList_;
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  JavaIoByteArrayOutputStream *buf = new_JavaIoByteArrayOutputStream_init();
  IOSShortArray *nameTypesSeen = [IOSShortArray newArrayWithLength:0];
  for (jint i = 0; i < [((JavaUtilVector *) nil_chk(serverNameList_)) size]; ++i) {
    LibOrgBouncycastleCryptoTlsServerName *entry_ = (LibOrgBouncycastleCryptoTlsServerName *) cast_chk([((JavaUtilVector *) nil_chk(serverNameList_)) elementAtWithInt:i], [LibOrgBouncycastleCryptoTlsServerName class]);
    nameTypesSeen = LibOrgBouncycastleCryptoTlsServerNameList_checkNameTypeWithShortArray_withShort_(nameTypesSeen, [((LibOrgBouncycastleCryptoTlsServerName *) nil_chk(entry_)) getNameType]);
    if (nameTypesSeen == nil) {
      @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
    }
    [entry_ encodeWithJavaIoOutputStream:buf];
  }
  LibOrgBouncycastleCryptoTlsTlsUtils_checkUint16WithInt_([buf size]);
  LibOrgBouncycastleCryptoTlsTlsUtils_writeUint16WithInt_withJavaIoOutputStream_([buf size], output);
  LibOrgBouncycastleUtilIoStreams_writeBufToWithJavaIoByteArrayOutputStream_withJavaIoOutputStream_(buf, output);
}

+ (LibOrgBouncycastleCryptoTlsServerNameList *)parseWithJavaIoInputStream:(JavaIoInputStream *)input {
  return LibOrgBouncycastleCryptoTlsServerNameList_parseWithJavaIoInputStream_(input);
}

+ (IOSShortArray *)checkNameTypeWithShortArray:(IOSShortArray *)nameTypesSeen
                                     withShort:(jshort)nameType {
  return LibOrgBouncycastleCryptoTlsServerNameList_checkNameTypeWithShortArray_withShort_(nameTypesSeen, nameType);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaUtilVector;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsServerNameList;", 0x9, 4, 5, 3, -1, -1, -1 },
    { NULL, "[S", 0xa, 6, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaUtilVector:);
  methods[1].selector = @selector(getServerNameList);
  methods[2].selector = @selector(encodeWithJavaIoOutputStream:);
  methods[3].selector = @selector(parseWithJavaIoInputStream:);
  methods[4].selector = @selector(checkNameTypeWithShortArray:withShort:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serverNameList_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaUtilVector;", "encode", "LJavaIoOutputStream;", "LJavaIoIOException;", "parse", "LJavaIoInputStream;", "checkNameType", "[SS" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsServerNameList = { "ServerNameList", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsServerNameList;
}

@end

void LibOrgBouncycastleCryptoTlsServerNameList_initWithJavaUtilVector_(LibOrgBouncycastleCryptoTlsServerNameList *self, JavaUtilVector *serverNameList) {
  NSObject_init(self);
  if (serverNameList == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'serverNameList' must not be null");
  }
  self->serverNameList_ = serverNameList;
}

LibOrgBouncycastleCryptoTlsServerNameList *new_LibOrgBouncycastleCryptoTlsServerNameList_initWithJavaUtilVector_(JavaUtilVector *serverNameList) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsServerNameList, initWithJavaUtilVector_, serverNameList)
}

LibOrgBouncycastleCryptoTlsServerNameList *create_LibOrgBouncycastleCryptoTlsServerNameList_initWithJavaUtilVector_(JavaUtilVector *serverNameList) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsServerNameList, initWithJavaUtilVector_, serverNameList)
}

LibOrgBouncycastleCryptoTlsServerNameList *LibOrgBouncycastleCryptoTlsServerNameList_parseWithJavaIoInputStream_(JavaIoInputStream *input) {
  LibOrgBouncycastleCryptoTlsServerNameList_initialize();
  jint length = LibOrgBouncycastleCryptoTlsTlsUtils_readUint16WithJavaIoInputStream_(input);
  if (length < 1) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_decode_error);
  }
  IOSByteArray *data = LibOrgBouncycastleCryptoTlsTlsUtils_readFullyWithInt_withJavaIoInputStream_(length, input);
  JavaIoByteArrayInputStream *buf = new_JavaIoByteArrayInputStream_initWithByteArray_(data);
  IOSShortArray *nameTypesSeen = [IOSShortArray newArrayWithLength:0];
  JavaUtilVector *server_name_list = new_JavaUtilVector_init();
  while ([buf available] > 0) {
    LibOrgBouncycastleCryptoTlsServerName *entry_ = LibOrgBouncycastleCryptoTlsServerName_parseWithJavaIoInputStream_(buf);
    nameTypesSeen = LibOrgBouncycastleCryptoTlsServerNameList_checkNameTypeWithShortArray_withShort_(nameTypesSeen, [((LibOrgBouncycastleCryptoTlsServerName *) nil_chk(entry_)) getNameType]);
    if (nameTypesSeen == nil) {
      @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_illegal_parameter);
    }
    [server_name_list addElementWithId:entry_];
  }
  return new_LibOrgBouncycastleCryptoTlsServerNameList_initWithJavaUtilVector_(server_name_list);
}

IOSShortArray *LibOrgBouncycastleCryptoTlsServerNameList_checkNameTypeWithShortArray_withShort_(IOSShortArray *nameTypesSeen, jshort nameType) {
  LibOrgBouncycastleCryptoTlsServerNameList_initialize();
  if (!LibOrgBouncycastleCryptoTlsNameType_isValidWithShort_(nameType) || LibOrgBouncycastleUtilArrays_containsWithShortArray_withShort_(nameTypesSeen, nameType)) {
    return nil;
  }
  return LibOrgBouncycastleUtilArrays_appendWithShortArray_withShort_(nameTypesSeen, nameType);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsServerNameList)
