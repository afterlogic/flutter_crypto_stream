import Flutter
import UIKit
import Foundation
import RxSwift
public class SwiftCryptoPlugin: NSObject, FlutterPlugin,FlutterStreamHandler {
    var methodCallHandler : FlutterMethodCallHandler
    let pgpApi = LibComAfterlogicPgpPgpApi()
    let pgpUtilApi = LibComAfterlogicPgpPgpUtilApi()
    var output : LibComAfterlogicPgpPlatform_streamPlatformOutputStream?
    var input : LibComAfterlogicPgpPlatform_streamPlatformInputStream?
    var flutterCallback = FlutterCallback()
    let subject = BehaviorSubject<()->Void>(value: {})
    let disposable = CompositeDisposable()
    let serialBackground = SerialDispatchQueueScheduler.init(qos: .background)
    
    public override init() {
        disposable.insert(
            subject.observeOn(MainScheduler.instance)
                .subscribe({ it ->Void in
                    it.element?()
                })
        )
        
        methodCallHandler = {  (call: FlutterMethodCall, result: @escaping FlutterResult) -> Void in
            let arguments = call.arguments as! [Any]
            let route = call.method.components(separatedBy: ".")
            let algorithm = route[0]
            let method = route[1]
            
            print("\(algorithm).\(method)")
            
            if(algorithm == "pgp" && method == "sendData"){
                self.flutterCallback.data((arguments[0] as! FlutterStandardTypedData).data)
                self.flutterCallback.result = result
                return
            }
            
            Single<Any>.create { observer -> Disposable in
                do{
                    
                }catch{
                    observer(.error(error))
                }
            }
        }
    }
    
    public func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        <#code#>
    }
    
    public func onCancel(withArguments arguments: Any?) -> FlutterError? {
        output?.close()
        input?.close()
    }
    
    
    func methodExecute(_ algorithm: String, method: String, arguments: [Any]) throws -> Any{
        var arg = arguments.makeIterator()
        switch algorithm {
        case "aes":
            let fileData = (arg.next() as! FlutterStandardTypedData).data
            let rawData = (arg.next() as! String).data(using: .utf8)
            let iv = (arg.next() as! String).data(using: .utf8)
            let isLast = arg.next() as! Bool
            let isDecrypt = method == "decrypt"
        return Aes.performCryption(fileData, rawData!, iv!, isLast, isDecrypt)
        case "pgp":
            switch method {
            case "getKeyDescription":
                let key = arg.next() as! String
                let result = pgpUtilApi.getKeyDescription(with: key)
                return [result?.getLength(),result?.getEmails()?.accessibilityElements,result?.isPrivate()]

            case "createKeys":
                let length = arg.next() as! NSNumber
                let email = arg.next() as! String
                let passwrod = arg.next() as! String
                let result = pgpUtilApi.createKeys(with: jint.init(exactly: length)!, with: email, with: passwrod)
                return [result!.object(at: 0),result!.object(at: 1)]
            case "checkKeyPassword":
                let key = (arg.next() as! String)
                let password = arg.next() as! String
                return pgpUtilApi.checkKeyPassword(with: key, with: password)
            case "lastVerifyResult":
                return pgpApi.lastVerifyResult_
            case "sign":
                let 
            case "verify": break
            default:
                throw NotImplemented()
            }
            break
        default:
            throw NotImplemented()
        }
    }
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        
        let messanger = registrar.messenger()
        let channel = FlutterMethodChannel(name: "crypto_method", binaryMessenger: messanger)
        let event = FlutterEventChannel(name: "crypto_event", binaryMessenger: messanger)
        let plugin = SwiftCryptoPlugin()
        event.setStreamHandler(plugin)
        channel.setMethodCallHandler(plugin.methodCallHandler)
    }
}
class FlutterCallback: LibComAfterlogicPgpPlatform_streamStreamCallback    {
    var inputStream: LibComAfterlogicPgpPlatform_streamPlatformInputStream?
    var result:  FlutterResult?
    
    func data(_ data:Data){
        inputStream?.addBuffer(with: IOSByteArray.init(nsData: data))
    }
    
    override func invoke() {
        
    }
}

class NotImplemented : Error{
    
}
