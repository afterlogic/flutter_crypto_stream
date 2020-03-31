#import "crypto_stream.h"
#import <crypto_stream/crypto_stream-Swift.h>


@implementation crypto_stream
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftCryptoStreamPlugin registerWithRegistrar:registrar];
}
@end
