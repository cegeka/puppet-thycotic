require 'spec_helper'
require 'logging'
require 'soap/wsdlDriver' 
require 'filecache'
require File.join(File.dirname(__FILE__), '../../lib/puppet/parser/functions/thycotic.rb')

# Enable rspec-mock
RSpec.configure do |config|
  config.mock_framework = :rspec
end

#Logging.logger.root.appenders = nil
Logging.logger.root.appenders = Logging.appenders.stdout
Logging.logger.root.level = :info

# Create a fake FileCache object that we can use to test the
# caching in our Thycotic object without actually writing to disk.
class FakeCache
  def initialize(name, path, ttl)
    @cache = {}
  end

  def set(key, value)
    @cache[key] = value
  end

  def get(key)
    @cache[key]
  end
end


describe Thycotic do
  before :each do
    # Mock the SOAP WSDL Driver object
    @driver = double('driver', :wiredump_file_base= => nil)
    factory = double('SOAP::WSDLDriverFactory')
    factory.should_receive(:create_rpc_driver).once.and_return(driver = @driver)
    SOAP::WSDLDriverFactory.should_receive(:new).and_return(factory)

    # Mock up the FileCache object so that each time its called we actually
    # supply our FakeCache object
    stub_const("FileCache", FakeCache)

    # Instantiate a Thycotic object
    params = {
      :username   => 'username',
      :password   => 'password',
      :orgcode    => 'orgcode',
      :domain     => 'domain',
      :serviceurl => 'http://unittest.com',
      :cache_path => nil,
    }
    @thycotic = Thycotic.new(params)
  end

  it "#new" do
    @thycotic.should be_an_instance_of Thycotic
  end

  it "#getDriver should return the same @driver every time" do
    driver_1 = @thycotic.send(:getDriver)
    driver_2 = @thycotic.send(:getDriver)
    driver_3 = @thycotic.send(:getDriver)
    driver_3.should == driver_2
    driver_2.should == driver_1
  end

  it "#new should fail with missing params" do
    expect { Thycotic.new({}) }.to raise_error(/Missing/)
  end
end
