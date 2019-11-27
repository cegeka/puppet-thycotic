source "https://rubygems.org"

# Required for unit testing
gem 'puppet', '< 4.0.0'
gem 'facter'
gem 'rake'
gem 'rspec-puppet'

# Required for the module itself
gem 'parseconfig'
gem 'filecache'

# Though we don't call soap4r methods directly, installing the
# module makes several soap+ssl warnings dissapear
if RUBY_VERSION == "1.8.7"
  gem 'soap4r'

  # https://github.com/rspec/rspec-core/issues/1864
  gem 'rspec', '= 3.1.0'
else
  gem 'soap4r-ruby1.9'
  gem 'rspec-puppet'
end
