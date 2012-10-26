#!/usr/bin/ruby
#
# Copyright 2012 Nextdoor.com, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# The 'thycotic_getsecret' function returns a hash to the user with any secrets that
# have been requested. The data is agressively cached because it should not change
# very often.
#
# Example usage:
#   $aws_creds = thycotic_getsecret('539820', 'secret_name')
#
# Returns:
#   $aws_creds = 'foo'

require File.join(File.dirname(__FILE__), 'thycotic.rb')
require File.join(File.dirname(__FILE__), 'parseconfig.rb')

module Puppet::Parser::Functions
  newfunction(:thycotic_getsecret, :type => :rvalue) do |args|
    secretid = args[0]
    secretname = args[1]

    # Get our auth options from the config file, or fail.
    begin
      config = ParseConfig.new('/etc/puppet/thycotic.conf')
    rescue
      raise Puppet::ParseError, "Could not load up Thycotic Secret Server credentials from /etc/puppet/thycotic.conf."
    end

    thycotic = Thycotic.new(config.get_value('url'), config.get_value('user'), config.get_value('password'), config.get_value('orgcode'))
    secret = thycotic.getSecret(secretid)

    # Walk through the returned elements of the hash, and look for the one we want.
    if secret.has_key?(secretname)
      if secret.has_key?(secretname) == nil
        raise Puppet::ParseError, "Secret returned by Thycotic.getSecret(#{secretid}) was 'nil'. This is bad, erroring out."
      else
        return secret[secretname].to_s
      end
    end

    raise Puppet::ParseError, "Could not retrieve SecretID #{secretid} from the Thycotic Secret Servers or our local cache."
  end
end

