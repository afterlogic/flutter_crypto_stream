#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#
Pod::Spec.new do |s|
  s.name             = 'crypto_stream'
  s.version          = '0.0.1'
  s.summary          = 'A new Flutter project.'
  s.description      = <<-DESC
A new Flutter project.
                       DESC
  s.homepage         = 'http://example.com'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Your Company' => 'email@example.com' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'
  s.dependency 'Flutter'
  s.ios.deployment_target = '8.0'

  s.xcconfig = { 
    'LIBRARY_SEARCH_PATHS' => '../dist/lib',
    'HEADER_SEARCH_PATHS' => '../dist/frameworks/JRE.framework/Headers',
  }

  s.libraries = 'jre_emul', 'z', 'iconv'

  s.static_framework = true 
  s.dependency 'RxSwift', '~> 5'
  s.dependency 'OpenSSL-Universal', '~> 1.0.2.17'
end

