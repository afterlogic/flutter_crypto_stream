//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x500/style/IETFUtils.java
//

#include "ASN1Encodable.h"
#include "ASN1Encoding.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "ASN1String.h"
#include "AttributeTypeAndValue.h"
#include "DERUniversalString.h"
#include "Hex.h"
#include "IETFUtils.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "RDN.h"
#include "Strings.h"
#include "X500Name.h"
#include "X500NameBuilder.h"
#include "X500NameStyle.h"
#include "X500NameTokenizer.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/StringBuffer.h"
#include "java/util/Enumeration.h"
#include "java/util/Hashtable.h"
#include "java/util/Vector.h"

@interface LibOrgBouncycastleAsn1X500StyleIETFUtils ()

+ (NSString *)unescapeWithNSString:(NSString *)elt;

+ (jboolean)isHexDigitWithChar:(jchar)c;

+ (jint)convertHexWithChar:(jchar)c;

+ (IOSObjectArray *)toValueArrayWithJavaUtilVector:(JavaUtilVector *)values;

+ (IOSObjectArray *)toOIDArrayWithJavaUtilVector:(JavaUtilVector *)oids;

+ (NSString *)bytesToStringWithByteArray:(IOSByteArray *)data;

+ (LibOrgBouncycastleAsn1ASN1Primitive *)decodeObjectWithNSString:(NSString *)oValue;

+ (jboolean)atvAreEqualWithLibOrgBouncycastleAsn1X500AttributeTypeAndValue:(LibOrgBouncycastleAsn1X500AttributeTypeAndValue *)atv1
                       withLibOrgBouncycastleAsn1X500AttributeTypeAndValue:(LibOrgBouncycastleAsn1X500AttributeTypeAndValue *)atv2;

@end

__attribute__((unused)) static NSString *LibOrgBouncycastleAsn1X500StyleIETFUtils_unescapeWithNSString_(NSString *elt);

__attribute__((unused)) static jboolean LibOrgBouncycastleAsn1X500StyleIETFUtils_isHexDigitWithChar_(jchar c);

__attribute__((unused)) static jint LibOrgBouncycastleAsn1X500StyleIETFUtils_convertHexWithChar_(jchar c);

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastleAsn1X500StyleIETFUtils_toValueArrayWithJavaUtilVector_(JavaUtilVector *values);

__attribute__((unused)) static IOSObjectArray *LibOrgBouncycastleAsn1X500StyleIETFUtils_toOIDArrayWithJavaUtilVector_(JavaUtilVector *oids);

__attribute__((unused)) static NSString *LibOrgBouncycastleAsn1X500StyleIETFUtils_bytesToStringWithByteArray_(IOSByteArray *data);

__attribute__((unused)) static LibOrgBouncycastleAsn1ASN1Primitive *LibOrgBouncycastleAsn1X500StyleIETFUtils_decodeObjectWithNSString_(NSString *oValue);

__attribute__((unused)) static jboolean LibOrgBouncycastleAsn1X500StyleIETFUtils_atvAreEqualWithLibOrgBouncycastleAsn1X500AttributeTypeAndValue_withLibOrgBouncycastleAsn1X500AttributeTypeAndValue_(LibOrgBouncycastleAsn1X500AttributeTypeAndValue *atv1, LibOrgBouncycastleAsn1X500AttributeTypeAndValue *atv2);

@implementation LibOrgBouncycastleAsn1X500StyleIETFUtils

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (NSString *)unescapeWithNSString:(NSString *)elt {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_unescapeWithNSString_(elt);
}

+ (jboolean)isHexDigitWithChar:(jchar)c {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_isHexDigitWithChar_(c);
}

+ (jint)convertHexWithChar:(jchar)c {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_convertHexWithChar_(c);
}

+ (IOSObjectArray *)rDNsFromStringWithNSString:(NSString *)name
   withLibOrgBouncycastleAsn1X500X500NameStyle:(id<LibOrgBouncycastleAsn1X500X500NameStyle>)x500Style {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_rDNsFromStringWithNSString_withLibOrgBouncycastleAsn1X500X500NameStyle_(name, x500Style);
}

+ (IOSObjectArray *)toValueArrayWithJavaUtilVector:(JavaUtilVector *)values {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_toValueArrayWithJavaUtilVector_(values);
}

+ (IOSObjectArray *)toOIDArrayWithJavaUtilVector:(JavaUtilVector *)oids {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_toOIDArrayWithJavaUtilVector_(oids);
}

+ (IOSObjectArray *)findAttrNamesForOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                                withJavaUtilHashtable:(JavaUtilHashtable *)lookup {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_findAttrNamesForOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaUtilHashtable_(oid, lookup);
}

+ (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)decodeAttrNameWithNSString:(NSString *)name
                                                     withJavaUtilHashtable:(JavaUtilHashtable *)lookUp {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_decodeAttrNameWithNSString_withJavaUtilHashtable_(name, lookUp);
}

+ (id<LibOrgBouncycastleAsn1ASN1Encodable>)valueFromHexStringWithNSString:(NSString *)str
                                                                  withInt:(jint)off {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_valueFromHexStringWithNSString_withInt_(str, off);
}

+ (void)appendRDNWithJavaLangStringBuffer:(JavaLangStringBuffer *)buf
        withLibOrgBouncycastleAsn1X500RDN:(LibOrgBouncycastleAsn1X500RDN *)rdn
                    withJavaUtilHashtable:(JavaUtilHashtable *)oidSymbols {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_appendRDNWithJavaLangStringBuffer_withLibOrgBouncycastleAsn1X500RDN_withJavaUtilHashtable_(buf, rdn, oidSymbols);
}

+ (void)appendTypeAndValueWithJavaLangStringBuffer:(JavaLangStringBuffer *)buf
withLibOrgBouncycastleAsn1X500AttributeTypeAndValue:(LibOrgBouncycastleAsn1X500AttributeTypeAndValue *)typeAndValue
                             withJavaUtilHashtable:(JavaUtilHashtable *)oidSymbols {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_appendTypeAndValueWithJavaLangStringBuffer_withLibOrgBouncycastleAsn1X500AttributeTypeAndValue_withJavaUtilHashtable_(buf, typeAndValue, oidSymbols);
}

+ (NSString *)valueToStringWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)value {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_valueToStringWithLibOrgBouncycastleAsn1ASN1Encodable_(value);
}

+ (NSString *)bytesToStringWithByteArray:(IOSByteArray *)data {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_bytesToStringWithByteArray_(data);
}

+ (NSString *)canonicalizeWithNSString:(NSString *)s {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_canonicalizeWithNSString_(s);
}

+ (LibOrgBouncycastleAsn1ASN1Primitive *)decodeObjectWithNSString:(NSString *)oValue {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_decodeObjectWithNSString_(oValue);
}

+ (NSString *)stripInternalSpacesWithNSString:(NSString *)str {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_stripInternalSpacesWithNSString_(str);
}

+ (jboolean)rDNAreEqualWithLibOrgBouncycastleAsn1X500RDN:(LibOrgBouncycastleAsn1X500RDN *)rdn1
                       withLibOrgBouncycastleAsn1X500RDN:(LibOrgBouncycastleAsn1X500RDN *)rdn2 {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_rDNAreEqualWithLibOrgBouncycastleAsn1X500RDN_withLibOrgBouncycastleAsn1X500RDN_(rdn1, rdn2);
}

+ (jboolean)atvAreEqualWithLibOrgBouncycastleAsn1X500AttributeTypeAndValue:(LibOrgBouncycastleAsn1X500AttributeTypeAndValue *)atv1
                       withLibOrgBouncycastleAsn1X500AttributeTypeAndValue:(LibOrgBouncycastleAsn1X500AttributeTypeAndValue *)atv2 {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_atvAreEqualWithLibOrgBouncycastleAsn1X500AttributeTypeAndValue_withLibOrgBouncycastleAsn1X500AttributeTypeAndValue_(atv1, atv2);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0xa, 0, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0xa, 2, 3, -1, -1, -1, -1 },
    { NULL, "I", 0xa, 4, 3, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1X500RDN;", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "[LNSString;", 0xa, 7, 8, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0xa, 9, 8, -1, -1, -1, -1 },
    { NULL, "[LNSString;", 0x9, 10, 11, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x9, 12, 13, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x9, 14, 15, 16, -1, -1, -1 },
    { NULL, "V", 0x9, 17, 18, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 19, 20, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 21, 22, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0xa, 23, 24, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 25, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0xa, 26, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 27, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 28, 29, -1, -1, -1, -1 },
    { NULL, "Z", 0xa, 30, 31, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(unescapeWithNSString:);
  methods[2].selector = @selector(isHexDigitWithChar:);
  methods[3].selector = @selector(convertHexWithChar:);
  methods[4].selector = @selector(rDNsFromStringWithNSString:withLibOrgBouncycastleAsn1X500X500NameStyle:);
  methods[5].selector = @selector(toValueArrayWithJavaUtilVector:);
  methods[6].selector = @selector(toOIDArrayWithJavaUtilVector:);
  methods[7].selector = @selector(findAttrNamesForOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withJavaUtilHashtable:);
  methods[8].selector = @selector(decodeAttrNameWithNSString:withJavaUtilHashtable:);
  methods[9].selector = @selector(valueFromHexStringWithNSString:withInt:);
  methods[10].selector = @selector(appendRDNWithJavaLangStringBuffer:withLibOrgBouncycastleAsn1X500RDN:withJavaUtilHashtable:);
  methods[11].selector = @selector(appendTypeAndValueWithJavaLangStringBuffer:withLibOrgBouncycastleAsn1X500AttributeTypeAndValue:withJavaUtilHashtable:);
  methods[12].selector = @selector(valueToStringWithLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[13].selector = @selector(bytesToStringWithByteArray:);
  methods[14].selector = @selector(canonicalizeWithNSString:);
  methods[15].selector = @selector(decodeObjectWithNSString:);
  methods[16].selector = @selector(stripInternalSpacesWithNSString:);
  methods[17].selector = @selector(rDNAreEqualWithLibOrgBouncycastleAsn1X500RDN:withLibOrgBouncycastleAsn1X500RDN:);
  methods[18].selector = @selector(atvAreEqualWithLibOrgBouncycastleAsn1X500AttributeTypeAndValue:withLibOrgBouncycastleAsn1X500AttributeTypeAndValue:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "unescape", "LNSString;", "isHexDigit", "C", "convertHex", "rDNsFromString", "LNSString;LLibOrgBouncycastleAsn1X500X500NameStyle;", "toValueArray", "LJavaUtilVector;", "toOIDArray", "findAttrNamesForOID", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LJavaUtilHashtable;", "decodeAttrName", "LNSString;LJavaUtilHashtable;", "valueFromHexString", "LNSString;I", "LJavaIoIOException;", "appendRDN", "LJavaLangStringBuffer;LLibOrgBouncycastleAsn1X500RDN;LJavaUtilHashtable;", "appendTypeAndValue", "LJavaLangStringBuffer;LLibOrgBouncycastleAsn1X500AttributeTypeAndValue;LJavaUtilHashtable;", "valueToString", "LLibOrgBouncycastleAsn1ASN1Encodable;", "bytesToString", "[B", "canonicalize", "decodeObject", "stripInternalSpaces", "rDNAreEqual", "LLibOrgBouncycastleAsn1X500RDN;LLibOrgBouncycastleAsn1X500RDN;", "atvAreEqual", "LLibOrgBouncycastleAsn1X500AttributeTypeAndValue;LLibOrgBouncycastleAsn1X500AttributeTypeAndValue;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X500StyleIETFUtils = { "IETFUtils", "lib.org.bouncycastle.asn1.x500.style", ptrTable, methods, NULL, 7, 0x1, 19, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X500StyleIETFUtils;
}

@end

void LibOrgBouncycastleAsn1X500StyleIETFUtils_init(LibOrgBouncycastleAsn1X500StyleIETFUtils *self) {
  NSObject_init(self);
}

LibOrgBouncycastleAsn1X500StyleIETFUtils *new_LibOrgBouncycastleAsn1X500StyleIETFUtils_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X500StyleIETFUtils, init)
}

LibOrgBouncycastleAsn1X500StyleIETFUtils *create_LibOrgBouncycastleAsn1X500StyleIETFUtils_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X500StyleIETFUtils, init)
}

NSString *LibOrgBouncycastleAsn1X500StyleIETFUtils_unescapeWithNSString_(NSString *elt) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  if ([((NSString *) nil_chk(elt)) java_length] == 0 || ([elt java_indexOf:'\\'] < 0 && [elt java_indexOf:'"'] < 0)) {
    return [elt java_trim];
  }
  IOSCharArray *elts = [elt java_toCharArray];
  jboolean escaped = false;
  jboolean quoted = false;
  JavaLangStringBuffer *buf = new_JavaLangStringBuffer_initWithInt_([elt java_length]);
  jint start = 0;
  if (IOSCharArray_Get(nil_chk(elts), 0) == '\\') {
    if (IOSCharArray_Get(elts, 1) == '#') {
      start = 2;
      (void) [buf appendWithNSString:@"\\#"];
    }
  }
  jboolean nonWhiteSpaceEncountered = false;
  jint lastEscaped = 0;
  jchar hex1 = 0;
  for (jint i = start; i != elts->size_; i++) {
    jchar c = IOSCharArray_Get(elts, i);
    if (c != ' ') {
      nonWhiteSpaceEncountered = true;
    }
    if (c == '"') {
      if (!escaped) {
        quoted = !quoted;
      }
      else {
        (void) [buf appendWithChar:c];
      }
      escaped = false;
    }
    else if (c == '\\' && !(escaped || quoted)) {
      escaped = true;
      lastEscaped = [buf java_length];
    }
    else {
      if (c == ' ' && !escaped && !nonWhiteSpaceEncountered) {
        continue;
      }
      if (escaped && LibOrgBouncycastleAsn1X500StyleIETFUtils_isHexDigitWithChar_(c)) {
        if (hex1 != 0) {
          (void) [buf appendWithChar:(jchar) (LibOrgBouncycastleAsn1X500StyleIETFUtils_convertHexWithChar_(hex1) * 16 + LibOrgBouncycastleAsn1X500StyleIETFUtils_convertHexWithChar_(c))];
          escaped = false;
          hex1 = 0;
          continue;
        }
        hex1 = c;
        continue;
      }
      (void) [buf appendWithChar:c];
      escaped = false;
    }
  }
  if ([buf java_length] > 0) {
    while ([buf charAtWithInt:[buf java_length] - 1] == ' ' && lastEscaped != ([buf java_length] - 1)) {
      [buf setLengthWithInt:[buf java_length] - 1];
    }
  }
  return [buf description];
}

jboolean LibOrgBouncycastleAsn1X500StyleIETFUtils_isHexDigitWithChar_(jchar c) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
}

jint LibOrgBouncycastleAsn1X500StyleIETFUtils_convertHexWithChar_(jchar c) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  if ('0' <= c && c <= '9') {
    return c - '0';
  }
  if ('a' <= c && c <= 'f') {
    return c - 'a' + 10;
  }
  return c - 'A' + 10;
}

IOSObjectArray *LibOrgBouncycastleAsn1X500StyleIETFUtils_rDNsFromStringWithNSString_withLibOrgBouncycastleAsn1X500X500NameStyle_(NSString *name, id<LibOrgBouncycastleAsn1X500X500NameStyle> x500Style) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  LibOrgBouncycastleAsn1X500StyleX500NameTokenizer *nTok = new_LibOrgBouncycastleAsn1X500StyleX500NameTokenizer_initWithNSString_(name);
  LibOrgBouncycastleAsn1X500X500NameBuilder *builder = new_LibOrgBouncycastleAsn1X500X500NameBuilder_initWithLibOrgBouncycastleAsn1X500X500NameStyle_(x500Style);
  while ([nTok hasMoreTokens]) {
    NSString *token = [nTok nextToken];
    if ([((NSString *) nil_chk(token)) java_indexOf:'+'] > 0) {
      LibOrgBouncycastleAsn1X500StyleX500NameTokenizer *pTok = new_LibOrgBouncycastleAsn1X500StyleX500NameTokenizer_initWithNSString_withChar_(token, '+');
      LibOrgBouncycastleAsn1X500StyleX500NameTokenizer *vTok = new_LibOrgBouncycastleAsn1X500StyleX500NameTokenizer_initWithNSString_withChar_([pTok nextToken], '=');
      NSString *attr = [vTok nextToken];
      if (![vTok hasMoreTokens]) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"badly formatted directory string");
      }
      NSString *value = [vTok nextToken];
      LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid = [((id<LibOrgBouncycastleAsn1X500X500NameStyle>) nil_chk(x500Style)) attrNameToOIDWithNSString:[((NSString *) nil_chk(attr)) java_trim]];
      if ([pTok hasMoreTokens]) {
        JavaUtilVector *oids = new_JavaUtilVector_init();
        JavaUtilVector *values = new_JavaUtilVector_init();
        [oids addElementWithId:oid];
        [values addElementWithId:LibOrgBouncycastleAsn1X500StyleIETFUtils_unescapeWithNSString_(value)];
        while ([pTok hasMoreTokens]) {
          vTok = new_LibOrgBouncycastleAsn1X500StyleX500NameTokenizer_initWithNSString_withChar_([pTok nextToken], '=');
          attr = [vTok nextToken];
          if (![vTok hasMoreTokens]) {
            @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"badly formatted directory string");
          }
          value = [vTok nextToken];
          oid = [x500Style attrNameToOIDWithNSString:[((NSString *) nil_chk(attr)) java_trim]];
          [oids addElementWithId:oid];
          [values addElementWithId:LibOrgBouncycastleAsn1X500StyleIETFUtils_unescapeWithNSString_(value)];
        }
        (void) [builder addMultiValuedRDNWithLibOrgBouncycastleAsn1ASN1ObjectIdentifierArray:LibOrgBouncycastleAsn1X500StyleIETFUtils_toOIDArrayWithJavaUtilVector_(oids) withNSStringArray:LibOrgBouncycastleAsn1X500StyleIETFUtils_toValueArrayWithJavaUtilVector_(values)];
      }
      else {
        (void) [builder addRDNWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:oid withNSString:LibOrgBouncycastleAsn1X500StyleIETFUtils_unescapeWithNSString_(value)];
      }
    }
    else {
      LibOrgBouncycastleAsn1X500StyleX500NameTokenizer *vTok = new_LibOrgBouncycastleAsn1X500StyleX500NameTokenizer_initWithNSString_withChar_(token, '=');
      NSString *attr = [vTok nextToken];
      if (![vTok hasMoreTokens]) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"badly formatted directory string");
      }
      NSString *value = [vTok nextToken];
      LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid = [((id<LibOrgBouncycastleAsn1X500X500NameStyle>) nil_chk(x500Style)) attrNameToOIDWithNSString:[((NSString *) nil_chk(attr)) java_trim]];
      (void) [builder addRDNWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:oid withNSString:LibOrgBouncycastleAsn1X500StyleIETFUtils_unescapeWithNSString_(value)];
    }
  }
  return [((LibOrgBouncycastleAsn1X500X500Name *) nil_chk([builder build])) getRDNs];
}

IOSObjectArray *LibOrgBouncycastleAsn1X500StyleIETFUtils_toValueArrayWithJavaUtilVector_(JavaUtilVector *values) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:[((JavaUtilVector *) nil_chk(values)) size] type:NSString_class_()];
  for (jint i = 0; i != tmp->size_; i++) {
    (void) IOSObjectArray_Set(tmp, i, (NSString *) cast_chk([values elementAtWithInt:i], [NSString class]));
  }
  return tmp;
}

IOSObjectArray *LibOrgBouncycastleAsn1X500StyleIETFUtils_toOIDArrayWithJavaUtilVector_(JavaUtilVector *oids) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:[((JavaUtilVector *) nil_chk(oids)) size] type:LibOrgBouncycastleAsn1ASN1ObjectIdentifier_class_()];
  for (jint i = 0; i != tmp->size_; i++) {
    (void) IOSObjectArray_Set(tmp, i, (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([oids elementAtWithInt:i], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]));
  }
  return tmp;
}

IOSObjectArray *LibOrgBouncycastleAsn1X500StyleIETFUtils_findAttrNamesForOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaUtilHashtable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, JavaUtilHashtable *lookup) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  jint count = 0;
  for (id<JavaUtilEnumeration> en = [((JavaUtilHashtable *) nil_chk(lookup)) elements]; [((id<JavaUtilEnumeration>) nil_chk(en)) hasMoreElements]; ) {
    if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(oid)) isEqual:[en nextElement]]) {
      count++;
    }
  }
  IOSObjectArray *aliases = [IOSObjectArray newArrayWithLength:count type:NSString_class_()];
  count = 0;
  for (id<JavaUtilEnumeration> en = [lookup keys]; [((id<JavaUtilEnumeration>) nil_chk(en)) hasMoreElements]; ) {
    NSString *key = (NSString *) cast_chk([en nextElement], [NSString class]);
    if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(oid)) isEqual:[lookup getWithId:key]]) {
      (void) IOSObjectArray_Set(aliases, count++, key);
    }
  }
  return aliases;
}

LibOrgBouncycastleAsn1ASN1ObjectIdentifier *LibOrgBouncycastleAsn1X500StyleIETFUtils_decodeAttrNameWithNSString_withJavaUtilHashtable_(NSString *name, JavaUtilHashtable *lookUp) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  if ([((NSString *) nil_chk(LibOrgBouncycastleUtilStrings_toUpperCaseWithNSString_(name))) java_hasPrefix:@"OID."]) {
    return new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_([((NSString *) nil_chk(name)) java_substring:4]);
  }
  else if ([((NSString *) nil_chk(name)) charAtWithInt:0] >= '0' && [name charAtWithInt:0] <= '9') {
    return new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(name);
  }
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([((JavaUtilHashtable *) nil_chk(lookUp)) getWithId:LibOrgBouncycastleUtilStrings_toLowerCaseWithNSString_(name)], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
  if (oid == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$$", @"Unknown object id - ", name, @" - passed to distinguished name"));
  }
  return oid;
}

id<LibOrgBouncycastleAsn1ASN1Encodable> LibOrgBouncycastleAsn1X500StyleIETFUtils_valueFromHexStringWithNSString_withInt_(NSString *str, jint off) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  IOSByteArray *data = [IOSByteArray newArrayWithLength:([((NSString *) nil_chk(str)) java_length] - off) / 2];
  for (jint index = 0; index != data->size_; index++) {
    jchar left = [str charAtWithInt:(index * 2) + off];
    jchar right = [str charAtWithInt:(index * 2) + off + 1];
    *IOSByteArray_GetRef(data, index) = (jbyte) ((JreLShift32(LibOrgBouncycastleAsn1X500StyleIETFUtils_convertHexWithChar_(left), 4)) | LibOrgBouncycastleAsn1X500StyleIETFUtils_convertHexWithChar_(right));
  }
  return LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(data);
}

void LibOrgBouncycastleAsn1X500StyleIETFUtils_appendRDNWithJavaLangStringBuffer_withLibOrgBouncycastleAsn1X500RDN_withJavaUtilHashtable_(JavaLangStringBuffer *buf, LibOrgBouncycastleAsn1X500RDN *rdn, JavaUtilHashtable *oidSymbols) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  if ([((LibOrgBouncycastleAsn1X500RDN *) nil_chk(rdn)) isMultiValued]) {
    IOSObjectArray *atv = [rdn getTypesAndValues];
    jboolean firstAtv = true;
    for (jint j = 0; j != ((IOSObjectArray *) nil_chk(atv))->size_; j++) {
      if (firstAtv) {
        firstAtv = false;
      }
      else {
        (void) [((JavaLangStringBuffer *) nil_chk(buf)) appendWithChar:'+'];
      }
      LibOrgBouncycastleAsn1X500StyleIETFUtils_appendTypeAndValueWithJavaLangStringBuffer_withLibOrgBouncycastleAsn1X500AttributeTypeAndValue_withJavaUtilHashtable_(buf, IOSObjectArray_Get(atv, j), oidSymbols);
    }
  }
  else {
    if ([rdn getFirst] != nil) {
      LibOrgBouncycastleAsn1X500StyleIETFUtils_appendTypeAndValueWithJavaLangStringBuffer_withLibOrgBouncycastleAsn1X500AttributeTypeAndValue_withJavaUtilHashtable_(buf, [rdn getFirst], oidSymbols);
    }
  }
}

void LibOrgBouncycastleAsn1X500StyleIETFUtils_appendTypeAndValueWithJavaLangStringBuffer_withLibOrgBouncycastleAsn1X500AttributeTypeAndValue_withJavaUtilHashtable_(JavaLangStringBuffer *buf, LibOrgBouncycastleAsn1X500AttributeTypeAndValue *typeAndValue, JavaUtilHashtable *oidSymbols) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  NSString *sym = (NSString *) cast_chk([((JavaUtilHashtable *) nil_chk(oidSymbols)) getWithId:[((LibOrgBouncycastleAsn1X500AttributeTypeAndValue *) nil_chk(typeAndValue)) getType]], [NSString class]);
  if (sym != nil) {
    (void) [((JavaLangStringBuffer *) nil_chk(buf)) appendWithNSString:sym];
  }
  else {
    (void) [((JavaLangStringBuffer *) nil_chk(buf)) appendWithNSString:[((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([typeAndValue getType])) getId]];
  }
  (void) [buf appendWithChar:'='];
  (void) [buf appendWithNSString:LibOrgBouncycastleAsn1X500StyleIETFUtils_valueToStringWithLibOrgBouncycastleAsn1ASN1Encodable_([typeAndValue getValue])];
}

NSString *LibOrgBouncycastleAsn1X500StyleIETFUtils_valueToStringWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> value) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  JavaLangStringBuffer *vBuf = new_JavaLangStringBuffer_init();
  if ([LibOrgBouncycastleAsn1ASN1String_class_() isInstance:value] && !([value isKindOfClass:[LibOrgBouncycastleAsn1DERUniversalString class]])) {
    NSString *v = [((id<LibOrgBouncycastleAsn1ASN1String>) nil_chk(((id<LibOrgBouncycastleAsn1ASN1String>) cast_check(value, LibOrgBouncycastleAsn1ASN1String_class_())))) getString];
    if ([((NSString *) nil_chk(v)) java_length] > 0 && [v charAtWithInt:0] == '#') {
      (void) [vBuf appendWithNSString:JreStrcat("C$", '\\', v)];
    }
    else {
      (void) [vBuf appendWithNSString:v];
    }
  }
  else {
    @try {
      (void) [vBuf appendWithNSString:JreStrcat("C$", '#', LibOrgBouncycastleAsn1X500StyleIETFUtils_bytesToStringWithByteArray_(LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_([((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk([((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(value)) toASN1Primitive])) getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER])))];
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Other value has no encoded form");
    }
  }
  jint end = [vBuf java_length];
  jint index = 0;
  if ([vBuf java_length] >= 2 && [vBuf charAtWithInt:0] == '\\' && [vBuf charAtWithInt:1] == '#') {
    index += 2;
  }
  while (index != end) {
    if (([vBuf charAtWithInt:index] == ',') || ([vBuf charAtWithInt:index] == '"') || ([vBuf charAtWithInt:index] == '\\') || ([vBuf charAtWithInt:index] == '+') || ([vBuf charAtWithInt:index] == '=') || ([vBuf charAtWithInt:index] == '<') || ([vBuf charAtWithInt:index] == '>') || ([vBuf charAtWithInt:index] == ';')) {
      (void) [vBuf insertWithInt:index withNSString:@"\\"];
      index++;
      end++;
    }
    index++;
  }
  jint start = 0;
  if ([vBuf java_length] > 0) {
    while ([vBuf java_length] > start && [vBuf charAtWithInt:start] == ' ') {
      (void) [vBuf insertWithInt:start withNSString:@"\\"];
      start += 2;
    }
  }
  jint endBuf = [vBuf java_length] - 1;
  while (endBuf >= 0 && [vBuf charAtWithInt:endBuf] == ' ') {
    (void) [vBuf insertWithInt:endBuf withChar:'\\'];
    endBuf--;
  }
  return [vBuf description];
}

NSString *LibOrgBouncycastleAsn1X500StyleIETFUtils_bytesToStringWithByteArray_(IOSByteArray *data) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  IOSCharArray *cs = [IOSCharArray newArrayWithLength:((IOSByteArray *) nil_chk(data))->size_];
  for (jint i = 0; i != cs->size_; i++) {
    *IOSCharArray_GetRef(cs, i) = (jchar) (IOSByteArray_Get(data, i) & (jint) 0xff);
  }
  return [NSString java_stringWithCharacters:cs];
}

NSString *LibOrgBouncycastleAsn1X500StyleIETFUtils_canonicalizeWithNSString_(NSString *s) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  NSString *value = LibOrgBouncycastleUtilStrings_toLowerCaseWithNSString_(s);
  if ([((NSString *) nil_chk(value)) java_length] > 0 && [value charAtWithInt:0] == '#') {
    LibOrgBouncycastleAsn1ASN1Primitive *obj = LibOrgBouncycastleAsn1X500StyleIETFUtils_decodeObjectWithNSString_(value);
    if ([LibOrgBouncycastleAsn1ASN1String_class_() isInstance:obj]) {
      value = LibOrgBouncycastleUtilStrings_toLowerCaseWithNSString_([((id<LibOrgBouncycastleAsn1ASN1String>) nil_chk(((id<LibOrgBouncycastleAsn1ASN1String>) cast_check(obj, LibOrgBouncycastleAsn1ASN1String_class_())))) getString]);
    }
  }
  if ([((NSString *) nil_chk(value)) java_length] > 1) {
    jint start = 0;
    while (start + 1 < [value java_length] && [value charAtWithInt:start] == '\\' && [value charAtWithInt:start + 1] == ' ') {
      start += 2;
    }
    jint end = [value java_length] - 1;
    while (end - 1 > 0 && [value charAtWithInt:end - 1] == '\\' && [value charAtWithInt:end] == ' ') {
      end -= 2;
    }
    if (start > 0 || end < [value java_length] - 1) {
      value = [value java_substring:start endIndex:end + 1];
    }
  }
  value = LibOrgBouncycastleAsn1X500StyleIETFUtils_stripInternalSpacesWithNSString_(value);
  return value;
}

LibOrgBouncycastleAsn1ASN1Primitive *LibOrgBouncycastleAsn1X500StyleIETFUtils_decodeObjectWithNSString_(NSString *oValue) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  @try {
    return LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(LibOrgBouncycastleUtilEncodersHex_decodeWithNSString_([((NSString *) nil_chk(oValue)) java_substring:1]));
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$@", @"unknown encoding in name: ", e));
  }
}

NSString *LibOrgBouncycastleAsn1X500StyleIETFUtils_stripInternalSpacesWithNSString_(NSString *str) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  JavaLangStringBuffer *res = new_JavaLangStringBuffer_init();
  if ([((NSString *) nil_chk(str)) java_length] != 0) {
    jchar c1 = [str charAtWithInt:0];
    (void) [res appendWithChar:c1];
    for (jint k = 1; k < [str java_length]; k++) {
      jchar c2 = [str charAtWithInt:k];
      if (!(c1 == ' ' && c2 == ' ')) {
        (void) [res appendWithChar:c2];
      }
      c1 = c2;
    }
  }
  return [res description];
}

jboolean LibOrgBouncycastleAsn1X500StyleIETFUtils_rDNAreEqualWithLibOrgBouncycastleAsn1X500RDN_withLibOrgBouncycastleAsn1X500RDN_(LibOrgBouncycastleAsn1X500RDN *rdn1, LibOrgBouncycastleAsn1X500RDN *rdn2) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  if ([((LibOrgBouncycastleAsn1X500RDN *) nil_chk(rdn1)) isMultiValued]) {
    if ([((LibOrgBouncycastleAsn1X500RDN *) nil_chk(rdn2)) isMultiValued]) {
      IOSObjectArray *atvs1 = [rdn1 getTypesAndValues];
      IOSObjectArray *atvs2 = [rdn2 getTypesAndValues];
      if (((IOSObjectArray *) nil_chk(atvs1))->size_ != ((IOSObjectArray *) nil_chk(atvs2))->size_) {
        return false;
      }
      for (jint i = 0; i != atvs1->size_; i++) {
        if (!LibOrgBouncycastleAsn1X500StyleIETFUtils_atvAreEqualWithLibOrgBouncycastleAsn1X500AttributeTypeAndValue_withLibOrgBouncycastleAsn1X500AttributeTypeAndValue_(IOSObjectArray_Get(atvs1, i), IOSObjectArray_Get(atvs2, i))) {
          return false;
        }
      }
    }
    else {
      return false;
    }
  }
  else {
    if (![((LibOrgBouncycastleAsn1X500RDN *) nil_chk(rdn2)) isMultiValued]) {
      return LibOrgBouncycastleAsn1X500StyleIETFUtils_atvAreEqualWithLibOrgBouncycastleAsn1X500AttributeTypeAndValue_withLibOrgBouncycastleAsn1X500AttributeTypeAndValue_([rdn1 getFirst], [rdn2 getFirst]);
    }
    else {
      return false;
    }
  }
  return true;
}

jboolean LibOrgBouncycastleAsn1X500StyleIETFUtils_atvAreEqualWithLibOrgBouncycastleAsn1X500AttributeTypeAndValue_withLibOrgBouncycastleAsn1X500AttributeTypeAndValue_(LibOrgBouncycastleAsn1X500AttributeTypeAndValue *atv1, LibOrgBouncycastleAsn1X500AttributeTypeAndValue *atv2) {
  LibOrgBouncycastleAsn1X500StyleIETFUtils_initialize();
  if (atv1 == atv2) {
    return true;
  }
  if (atv1 == nil) {
    return false;
  }
  if (atv2 == nil) {
    return false;
  }
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *o1 = [atv1 getType];
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *o2 = [atv2 getType];
  if (![((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(o1)) isEqual:o2]) {
    return false;
  }
  NSString *v1 = LibOrgBouncycastleAsn1X500StyleIETFUtils_canonicalizeWithNSString_(LibOrgBouncycastleAsn1X500StyleIETFUtils_valueToStringWithLibOrgBouncycastleAsn1ASN1Encodable_([atv1 getValue]));
  NSString *v2 = LibOrgBouncycastleAsn1X500StyleIETFUtils_canonicalizeWithNSString_(LibOrgBouncycastleAsn1X500StyleIETFUtils_valueToStringWithLibOrgBouncycastleAsn1ASN1Encodable_([atv2 getValue]));
  if (![((NSString *) nil_chk(v1)) isEqual:v2]) {
    return false;
  }
  return true;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X500StyleIETFUtils)
