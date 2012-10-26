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
# The 'thycotic' module is a Ruby class that retrieves data
# from Thycotic's 'Secret Server' at a given URL with specified credentials.
#
# For security purposes, these credentials are loaded up from a local file
# that must be *manually* placed into /etc/puppet/thycotic
#
# Example Usage:
#   require 'thycotic.rb'
#   thycotic = Thycotic.new('https://www.secretserveronline.com/webservices/SSWebService.asmx', 'nextdoor', 'password', 'orgid')
#   secret = thycotic.getSecret(secretid)
#

# 'load' the rubygem file rather than requiring it. This loads it up, but allows
# us to re-load it later if we find our selves having to install a missing rubygem.
#load '/usr/local/lib/site_ruby/1.8/rubygems.rb'
require 'rubygems'
require 'timeout'
require 'net/https'
require 'uri'
require 'yaml'
require 'base64'

# Check if the required gems are available. If not, try to install them. Do not check
# for 'rubygems' or 'yaml', as those are stock and always available.
def gem_available?(name,realname)
  begin
    require "#{name}"
  rescue Exception=>e
    puts "Missing gem (#{name}), installing it..."
    `gem install #{realname} --no-ri --no-rdoc`
    Gem.clear_paths
    require "#{name}"
  end
end
gem_available?('filecache','filecache')
gem_available?('xmlsimple','xml-simple')

# The 'thycotic' class is used to retrieve passwords/keys from the Thycotic SecretServer Online
# by using their API.
class Thycotic
  def initialize(serviceurl, username, password, orgcode, domain = '', debug = true)
    @serviceurl = serviceurl
    @username = username
    @password = password
    @orgcode = orgcode
    @domain = domain
    @debug = debug

    # the cache should always be available... 
    @cache = FileCache.new("thycotic","/tmp", 1800)
    @long_term_cache = FileCache.new("thycotic_long_term","/tmp", 108000)

    puts "Thycotic(#{serviceurl}, #{username}, <password>, #{orgcode}, #{domain}, #{debug}) initialized...\n" if @debug
  end

  def getFile(secretid,fileid,token)
    tried = false
    begin
      url = "#{@serviceurl}/DownloadFileAttachmentByItemId?token=#{token}&secretId=#{secretid}&secretItemId=#{fileid}"
      puts "getFile(#{secretid},#{fileid},<token>): calling makeRequest(#{url})\n" if @debug
      data = makeRequest(url)

      # Check if there is evne a file to return. If the secret server says there isnt, then
      # return 'false'.
      if data['Errors'][0]['string'].to_s == 'File attachment not found.'
        # There is no atual data to return, but this is not a bad thing. There simply is no
        # key... so return false.
        puts "getFile(#{secretid},#{fileid},<token>): returning false, no file attachment found.\n" if @debug
        return false
      else
        # Make sure we got a file back.. if we did, return the content. Otherwise, raise an exception
        data = Base64.decode64(data['FileAttachment'][0]).to_s
        puts "getFile(#{secretid},#{fileid},<token>): file data:\n#{data}\n" if @debug
        return data
      end
    rescue Exception=>e
      if tried == false
        # Allow a single re-try downloading the file
        tried = true
        puts "getFile(#{secretid},#{fileid},<token>): Returned Exception (#{e}) ... trying again.\n" if @debug
        retry
      else
        # Now that we've tried twice and failed both times, raise an exception
        puts "getFile(#{secretid},#{fileid},<token>): Returned Exception (#{e}) ... done trying. Failing.\n" if @debug
        raise "Could not retrieve URL #{url} and Base64 decode it. Error: #{e}"
      end 
    end
  end

  def getSecret(secretid)
    # The logic here is that our secrets change very rarely.. therefore we'd rather pull from
    # cache almost every time than go out to the remote service and get the secret content. The
    # flow is this:
    #
    # is item in cache and not expired?
    # .. no?
    # .. .. Get item from API. Cache item. Successfull?
    # .. .. no? try returning item from long_term_cache
    # .. .. yes? return item from api, update cache.
    # .. yes?
    # .. .. return item from cache
    #
    if @cache.get(secretid) == nil
      # Get the item from API...
      begin
        token = getToken()
        url = "#{@serviceurl}/GetSecret?token=#{token}&secretId=#{secretid}"
        puts "getSecret(#{secretid}): calling makeRequest(#{url})\n" if @debug
        data = makeRequest(url)

        # We get a massive hash returned from Thyucotic.. strip it down
        secret_hash = {} 
        data['Secret'][0]['Items'][0]['SecretItem'].each do |secret|
          if secret.has_key?('FieldDisplayName')
            # In the event that we're looking at a File resource, we need to download the file.
            if secret['IsFile'][0] == 'true'
              content = getFile(secretid,secret['Id'][0],token)
            else
              content = secret['Value'][0]
            end

            if content != false
              puts "getSecret(#{secretid}): Got content for secret '#{secret['FieldDisplayName'][0]}'...\n" if @debug
              secret_hash[secret['FieldDisplayName'][0]] = content
            end
          end
        end

        # Never cache a 'nil' result. Ever.
        if secret_hash != nil
          # Now that we have the item, cache it.. then return it. We cache in two
          # caches because one is used as a 'backup' in case the API service is unavailable
          # for a long period of time.
          puts "getSecret(#{secretid}): Caching secret '#{secretid}'...\n" if @debug
          @cache.set(secretid,secret_hash.to_yaml)
          @long_term_cache.set(secretid,secret_hash.to_yaml)
          return secret_hash
        else
          raise "Retrieved secret was 'nil'. Invalid."
        end
      rescue Exception=>e
        # Last shot.. item was not in our regular cache, AND we couldn't get it
        # from the API service, so lets attempt to find it in our long term cache.
	begin
          puts "getSecret(#{secretid}): Secret unavailable from remote service (#{e}). Found secret in long-term cache. Returning Secret....\n" if @debug
          return YAML::load(@long_term_cache.get(secretid))
	rescue Exception =>e
	  raise "Could not retrieve secret from short or long_term cache, or the API services. Please troubleshoot: #{e}"
	end
      end
    else
      # The item was found in the cache...
      puts "getSecret(#{secretid}): Secret found in short-term cache... Returning Secret....\n" if @debug
      return YAML::load(@cache.get(secretid))
    end 
  end

  def checkToken(token)
    url = "#{@serviceurl}/GetTokenIsValid?&token=#{token}"
    puts "checkToken(#{token}): Checking if token is valid, calling makeRequest(#{url})...\n" if @debug
    data = makeRequest(url)
    tokenExpires = data['MaxOfflineSeconds'][0].to_i

    if tokenExpires > 0
      puts "checkToken(#{token}): is valid\n" if @debug
      return true
    else
      puts "checkToken(#{token}): is expired\n" if @debug
      return false
    end
  end

  def getToken()
    # Check if we have a token available in the cache or not.
    begin
      cached_token = YAML::load(@cache.get('token'))
      if checkToken(cached_token[0])
        return cached_token
      else
        raise 
      end
    rescue
      # Generate the URL to retreive a token
      url = "#{@serviceurl}/Authenticate?username=#{@username}&password=#{@password}&organization=#{@orgcode}&domain=#{@domain}"
      data = makeRequest(url)
      token = data['Token']
 
      # Before returning the token, cache it.
      @cache.set('token', token.to_yaml)

      # Now return the token
      return token
    end 
  end 

  def makeRequest(url)
    # Create the HTTP request object ... but dont use it yet
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.read_timeout = 3
    http.open_timeout = 3
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    # Now make the request and get the response back
    request = Net::HTTP::Get.new(uri.request_uri)
    xml_data = http.request(request).body

    # Parse the response with an XML parser and return it as a hash
    return XmlSimple.xml_in(xml_data)
  end
end
