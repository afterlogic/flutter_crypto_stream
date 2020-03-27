//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/ServerName.java
//

#include "AlertDescription.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NameType.h"
#include "ServerName.h"
#include "TlsFatalAlert.h"
#include "TlsUtils.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"

@implementation LibOrgBouncycastleCryptoTlsServerName

- (instancetype)initWithShort:(jshort)nameType
                       withId:(id)name {
  LibOrgBouncycastleCryptoTlsServerName_initWithShort_withId_(self, nameType, name);
  return self;
}

- (jshort)getNameType {
  return nameType_;
}

- (id)getName {
  return name_;
}

- (NSString *)getHostName {
  if (!LibOrgBouncycastleCryptoTlsServerName_isCorrectTypeWithShort_withId_(LibOrgBouncycastleCryptoTlsNameType_host_name, name_)) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"'name' is not a HostName string");
  }
  return (NSString *) cast_chk(name_, [NSString class]);
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  LibOrgBouncycastleCryptoTlsTlsUtils_writeUint8WithShort_withJavaIoOutputStream_(nameType_, output);
  {
    IOSByteArray *asciiEncoding;
    switch (nameType_) {
      case LibOrgBouncycastleCryptoTlsNameType_host_name:
      asciiEncoding = [((NSString *) nil_chk(((NSString *) cast_chk(name_, [NSString class])))) java_getBytesWithCharsetName:@"ASCII"];
      if (((IOSByteArray *) nil_chk(asciiEncoding))->size_ < 1) {
        @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
      }
      LibOrgBouncycastleCryptoTlsTlsUtils_writeOpaque16WithByteArray_withJavaIoOutputStream_(asciiEncoding, output);
      break;
      default:
      @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
    }
  }
}

+ (LibOrgBouncycastleCryptoTlsServerName *)parseWithJavaIoInputStream:(JavaIoInputStream *)input {
  return LibOrgBouncycastleCryptoTlsServerName_parseWithJavaIoInputStream_(input);
}

+ (jboolean)isCorrectTypeWithShort:(jshort)nameType
                            withId:(id)name {
  return LibOrgBouncycastleCryptoTlsServerName_isCorrectTypeWithShort_withId_(nameType, name);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "S", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsServerName;", 0x9, 4, 5, 3, -1, -1, -1 },
    { NULL, "Z", 0xc, 6, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithShort:withId:);
  methods[1].selector = @selector(getNameType);
  methods[2].selector = @selector(getName);
  methods[3].selector = @selector(getHostName);
  methods[4].selector = @selector(encodeWithJavaIoOutputStream:);
  methods[5].selector = @selector(parseWithJavaIoInputStream:);
  methods[6].selector = @selector(isCorrectTypeWithShort:withId:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "nameType_", "S", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "name_", "LNSObject;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "SLNSObject;", "encode", "LJavaIoOutputStream;", "LJavaIoIOException;", "parse", "LJavaIoInputStream;", "isCorrectType" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsServerName = { "ServerName", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsServerName;
}

@end

void LibOrgBouncycastleCryptoTlsServerName_initWithShort_withId_(LibOrgBouncycastleCryptoTlsServerName *self, jshort nameType, id name) {
  NSObject_init(self);
  if (!LibOrgBouncycastleCryptoTlsServerName_isCorrectTypeWithShort_withId_(nameType, name)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'name' is not an instance of the correct type");
  }
  self->nameType_ = nameType;
  self->name_ = name;
}

LibOrgBouncycastleCryptoTlsServerName *new_LibOrgBouncycastleCryptoTlsServerName_initWithShort_withId_(jshort nameType, id name) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsServerName, initWithShort_withId_, nameType, name)
}

LibOrgBouncycastleCryptoTlsServerName *create_LibOrgBouncycastleCryptoTlsServerName_initWithShort_withId_(jshort nameType, id name) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsServerName, initWithShort_withId_, nameType, name)
}

LibOrgBouncycastleCryptoTlsServerName *LibOrgBouncycastleCryptoTlsServerName_parseWithJavaIoInputStream_(JavaIoInputStream *input) {
  LibOrgBouncycastleCryptoTlsServerName_initialize();
  jshort name_type = LibOrgBouncycastleCryptoTlsTlsUtils_readUint8WithJavaIoInputStream_(input);
  id name;
  switch (name_type) {
    case LibOrgBouncycastleCryptoTlsNameType_host_name:
    {
      IOSByteArray *asciiEncoding = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque16WithJavaIoInputStream_(input);
      if (((IOSByteArray *) nil_chk(asciiEncoding))->size_ < 1) {
        @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_decode_error);
      }
      name = [NSString java_stringWithBytes:asciiEncoding charsetName:@"ASCII"];
      break;
    }
    default:
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_decode_error);
  }
  return new_LibOrgBouncycastleCryptoTlsServerName_initWithShort_withId_(name_type, name);
}

jboolean LibOrgBouncycastleCryptoTlsServerName_isCorrectTypeWithShort_withId_(jshort nameType, id name) {
  LibOrgBouncycastleCryptoTlsServerName_initialize();
  switch (nameType) {
    case LibOrgBouncycastleCryptoTlsNameType_host_name:
    return [name isKindOfClass:[NSString class]];
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'nameType' is an unsupported NameType");
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsServerName)