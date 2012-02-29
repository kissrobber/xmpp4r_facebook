spec = Gem::Specification.new do |s|
  s.name = 'xmpp4r_facebook'
  s.version = '0.1.1'
  s.summary = 'Expansion XMPP4R to authenticate with Facebook Connect in Ruby'
  s.description = 'Expansion XMPP4R to authenticate with Facebook Connect in Ruby'
  s.author = 'kissrobber'
  s.email = 'kissrobber@gmail.com'
  s.homepage = 'https://github.com/kissrobber'
  s.add_dependency 'xmpp4r'
  s.require_paths = ["lib"]
  s.files = Dir.glob("lib/**/*")
end