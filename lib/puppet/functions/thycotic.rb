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
#   thycotic = Thycotic.new( {
#      :username => 'user',
#      :password => 'password',
#      :orgcode  => 'orgcode',
#      :domain   => 'domain',
#      :debug    => true,
#      } )
#   secret = thycotic.getSecret(secretid)
#

require 'base64'
require 'etc'
require 'filecache'
require 'puppet'
require 'rubygems'
require 'timeout'
require 'yaml'
require "uri"
require "net/http"
require 'parseconfig'
require "json"

# Some static variables that control the overall behavior of the module
SHORT_TERM_CACHE_TIMEOUT=21600  # 6 hours
SHORT_TERM_CACHE_NAME='thycotic'
LONG_TERM_CACHE_TIMEOUT=108000
LONG_TERM_CACHE_NAME='thycotic-long-term'
CACHE_PATH='/tmp'
CACHE_DEFAULT_OWNER='puppet'
CACHE_DEFAULT_GROUP='puppet'
CACHE_DEFAULT_MODE=0750
DOMAIN_DEFAULT=''
CONNECT_TIMEOUT=60 # [sec]
SEND_TIMEOUT=120 # [sec]
RECEIVE_TIMEOUT=60 # [sec]
SSL_VERIFY_MODE='OpenSSL::SSL::VERIFY_NONE' # secretserver has a bad cert
SANITIZE_CONTENT=true
SERVICEURL=''

# The 'thycotic' class is used to retrieve passwords/keys from the Thycotic SecretServer Online
# by using their API.
class Thycotic
  # This is the class object initializer for this Thycotic interface
  #
  # * *Args*:
  #   - *params* -> A hash with the following keys:
  #     - +username+ -> The login username
  #     - +password+ -> The login password
  #     - +orgcode+ -> The login organization code associated with the above login
  #     - +domain+ ->  The login 'domain' that the above credentials are associated with
  #     - +serviceurl+ -> The remote web services URL
  #                     (default: https://www.secretserveronline.com/webservices/SSWebService.asmx)
  #     - +debug+ -> Should debug logging be enabled (strongly recommend you disable this, very insecure!)
  #                (default: false)
  #     - +log_stdout+ -> log to stdout, handy to debug issues consuming PIM secrets but can potentially expose sensitive information, use for local debug only.
  #     - +cache_path+ -> Filesystem location to cache results (default: /tmp)
  #
  def initialize(params)
    # Fill in any missing parameters to the supplied parameters hash
    @params = params
    @params[:serviceurl]       ||= SERVICEURL
    @params[:cache_path]       ||= CACHE_PATH
    @params[:debug]            ||= false
    @params[:cache_owner]      ||= CACHE_DEFAULT_OWNER
    @params[:cache_group]      ||= CACHE_DEFAULT_GROUP
    @params[:cache_mode]       ||= CACHE_DEFAULT_MODE
    @params[:domain]           ||= DOMAIN_DEFAULT
    @params[:connect_timeout]  ||= CONNECT_TIMEOUT
    @params[:send_timeout]     ||= SEND_TIMEOUT
    @params[:receive_timeout]  ||= RECEIVE_TIMEOUT
    @params[:ssl_verify_mode]  ||= SSL_VERIFY_MODE
    @params[:sanitize_content] ||= SANITIZE_CONTENT

    log("log_stdout enabled.")
    log("params: #{@params}")

    # Take just the serviceurl parameter and check if there is a 3xx redirect response code header.
    log("Validate serviceurl #{@params[:serviceurl]}")

    url = URI(@params[:serviceurl])
    https = Net::HTTP.new(url.host, url.port)
    https.use_ssl = true
    https.verify_mode = eval(@params[:ssl_verify_mode]) if @params[:ssl_verify_mode]
    https.open_timeout = @params[:connect_timeout] if @params[:connect_timeout]
    https.read_timeout = @params[:receive_timeout] if @params[:receive_timeout]

    request = Net::HTTP::Get.new(url)
    response = https.request(request)

    # HTTP response codes which are indicative of an actual redirect that should be followed. E.g.:
    # - 302: default HTTP response code for unauthenticated request, should not change the serviceurl.
    # - 307: valid redirect that should be followed, i.e.: when Secret Server is being migrated, moved, domain/url is being altered.
    # Other response codes have not been evaluated yet as we have not yet encountered them.
    rewrite_redirect_codes = [307]

    # If there is a HTTP response code, check if it is one defined above as one that warrants a serviceurl change.
    # We will set the redirect location (if any) to try and gracefully recover from potential failure in the secret fetching flow.
    if rewrite_redirect_codes.include?(response.code.to_i)
      if response['location']
        log("serviceurl param with value \"#{@params[:serviceurl]}\" has a #{response.code} redirect response code which is likely to break secret fetching. The serviceurl param value will be set to \"#{response['location']}\".")
        @params[:serviceurl] = response['location']
      else
        log("serviceurl param with value \"#{@params[:serviceurl]}\" has a #{response.code} redirect response code but no \"location\" header. Expect secret fetching to fail.")
      end
    else
      log("serviceurl param with value \"#{@params[:serviceurl]}\" has a #{response.code} response code which is not defined in the (hard-coded) rewrite_redirect_codes (#{rewrite_redirect_codes}) that are acted upon to change the serviceurl.")
    end

    # If debug logging is enabled, we log out our entire parameters dict,
    # including the password/username that were supplied. Debug mode is
    # dangerous and meant to only be used during troubleshooting.
    @params.each do |k,v|
      if k != :password
        log("Initialization params: #{k} => #{v}")
      end
    end

    # Make sure that the required parameters WERE supplied
    if @params[:username].nil? \
            or @params[:password].nil? \
            or @params[:orgcode].nil?
       raise 'Missing parameters. See header above for instructions.'
    end

    # Make sure that a short-term and long-term file cache is available.
    if not @params[:cache_path].nil?
      @cache = _init_cache(
        'short-term', SHORT_TERM_CACHE_NAME, SHORT_TERM_CACHE_TIMEOUT)

      @long_term_cache = _init_cache(
        'long-term', LONG_TERM_CACHE_NAME, LONG_TERM_CACHE_TIMEOUT)
    end
  end

  def _init_cache(description, cache_name, cache_timeout)
    # * *Args*:
    #   - +description+   -> Human readable name. Only used for logs.
    #   - +cache_name+    -> Filename of the cache. Does not include path.
    #   - +cache_timeout+ -> Seconds to keep cache values valid.
    #
    # * *Raises*:
    #   - ArgumentError for getpwnam and getgrnam if user/group does not exist
    #   - Errno::EPERM for chown and chmod if operation is not permitted.
    #
    # * *Returns*:
    #   - Newly created descriptor of the FileCache()
    #
    cache_file = @params[:cache_path] + '/' + cache_name

    log("Initializing `%s` cache in %s with timeout %s" % [
      description, cache_file, cache_timeout])

    # Create the file, set ownership and mode.
    cache = FileCache.new(cache_name, @params[:cache_path], cache_timeout)
    #_update_cache_permissions(cache_file)
    return cache
  end

  # def _update_cache_permissions(cache_file)
  #   # * *Args*:
  #   #   - +cache_file+ -> File descriptor for which to change mode and owner
  #   #
  #   if File.readlines("/proc/1/cgroup").grep(/docker|lxc|crio/).any?
  #     return true
  #   else
  #     owner = Etc.getpwnam(@params[:cache_owner]).uid
  #     group = Etc.getgrnam(@params[:cache_group]).gid

  #     FileUtils.chmod(@params[:cache_mode], cache_file)
  #     FileUtils.chown_R(owner, group, cache_file)
  #   end
  # end

  def log(msg, identifier = nil)
    # Reports a log messsage if debugging is enabled
    # Optionally print log messages to stdout if enabled
    #
    # * *Args*:
    #   - +msg+ -> String contents of the message to report
    #   - +identifier+ -> String contents of a helpful identifier, e.g.: filename where log() is invoked
    #

    if @params[:debug]
      Puppet.warning(msg)
    else
      Puppet.debug(msg)
    end

    if @params[:log_stdout]
      # If no identifier is set, set default value (this file name)
      if identifier.nil?
        identifier = 'thycotic.rb'
      end
      # Output identifier and msg to stdout
      puts "[#{identifier}] #{msg}"
    end
  end

  def getSecret(secretid)
    # * *Args*:
    #   - +secretid+ -> Secret ID to retrieve
    #
    # * *Returns*:
    #   - Hash containing key/value pairs from the secret retrieved looking like:
    #       hash = {
    #         "<secret field name>" = "<secret content>"
    #         "<secret field name>" = "<secret content>"
    #         "<secret field name>" = "<secret content>"
    #       }
    #
    # * *Raises*:
    #   - An exception in the event that the secret cannot be retrieved
    #
    log("--- Called getSecret(#{secretid}) --------------------------------------------------")
    $secret = (getSecretFromCache(@cache, secretid) ||
               getAndCacheSecretFromAPI(secretid) ||
               getSecretFromCache(@long_term_cache, secretid))

    if not $secret
      # Finally, if we got here then we raise an exception. We couldn't get the
      # secret value from any of the sources.
      raise "Could not retrieve secret with ID #{secretid} from short or long term cache, " \
            "or the API services. Please troubleshoot."
    end

    return $secret
  end

  private

  def getSecretFromCache(cache, secretid)
    # Returns a secret from a supplied cache object. Handles any exceptions
    # and returns either the secret, or a Nil value.
    #
    # * *Args*:
    #   - +cache+ -> The filecache object to search
    #   - +secretid+ -> The secretid to look for
    #
    # * *Returns*:
    #   - false: If no secret was found
    #   - Hash containing the secret from the filecache object
    #

    # Quick check. If the supplied cache object is nil, or the secret
    # id is nil, then just return nil.
    if cache.nil? or secretid.nil?
      # supplumental debug message if somehow both cache object and secret id are nil
      log("getSecretFromCache() with #{secretid}: cache object and secret id are both nil")
      return false
    end

    # Grab the name of the cache object for logging
    cache_name = cache.instance_variable_get("@root")

    # Attempt to get the Secret ID from the cache now
    log("Getting #{secretid} from #{cache_name}")
    begin
      # assign loaded value to var so we can return it after a debug message
      cached_secret = YAML::load(cache.get(secretid))
      # debug message, assuming variable assignment did not fail, we do not end up in rescue
      log("getSecretFromCache() with #{secretid}: found in cache")
      # return cached secret
      return cached_secret
    rescue Exception => e
      log("getSecretFromCache() with #{secretid}: not found in #{cache_name}.")
      return false
    end
  end

  def saveSecretToCache(cache, secretid, secretvalue)
    # Saves a supplied secret to the cache. Handles any exceptions and
    # returns quietly. Will output debug logging during a failure, but
    # thats it.
    #
    # * *Args*:
    #   - +cache+ -> The filecache object to write to
    #   - +secretid+ -> The secret ID number to use as the key
    #   - +Secretvalue+ -> The secret value to store
    #

    # Make sure that the three values were supplid. If any are Nil,
    # log and exit safely.
    log("Saving #{secretid} on #{cache}")
    if secretid.nil?
      log("Secret ID cannot be Nil!")
      return
    end
    if cache.nil?
      log("Caching disabled, not storing Secret ID #{secretid}")
      return
    end
    if secretvalue.nil?
      log("Missing value for Secret ID #{secretid}. Not storing.")
      return
    end

    # Grab the name of the cache object for logging
    cache_name = cache.instance_variable_get("@root")

    # Now try to save the secret to the cache. If it fails, just return.
    begin
      log("Saving Secret ID '#{secretid}' to #{cache_name}...\n")
      cache.set(secretid,secretvalue.to_yaml)
    rescue Exception =>e
      log("Failed saving Secret ID #{secretid} to #{cache_name}: #{e}.")
    end

    #_update_cache_permissions(cache_name)
  end

  def getAndCacheSecretFromAPI(secretid)
    # Contacts the API service and retreives the secret hash. Handles all
    # exceptions and either returns a Nil value, or the hash data from
    # the API.
    #
    # *Args*:
    #   - +secretid+ -> Secret ID to retrieve
    #
    # * *Returns*:
    #   - false: If no secret was found.
    #   - Hash containing key/value pairs from the secret retrieved looking like:
    #       hash = {
    #         "<secret field name>" = "<secret content>"
    #         "<secret field name>" = "<secret content>"
    #         "<secret field name>" = "<secret content>"
    #       }
    #

    # This whole thing is wrapped in a single Begin/Rescue loop because the failure
    # handling is the same no matter what. Return Nil and throw a log message.
    begin
      if @token.nil?
        # If @cache.get('token') fails for any reason, we're caught by
        # the 'rescue' statement below and a new token is generated.
        @token = @cache.get('rest_api_token')
      end

      tries=0
      max_tries=3

      # Do the API request for the secret that needs to be retrieved. Here we will also check if the token is still valid and if not rerequest it.
      # In case this fails we return false on the entire function with the correct response.
      # In case we receive anything else then 200 on the call after authentication, we a raise an error

      url = URI("#{@params[:serviceurl]}/api/v2/secrets/#{secretid}")
      https = Net::HTTP.new(url.host, url.port)
      https.use_ssl = true
      https.verify_mode = eval(@params[:ssl_verify_mode]) if @params[:ssl_verify_mode]
      https.open_timeout = @params[:connect_timeout] if @params[:connect_timeout]
      https.read_timeout = @params[:receive_timeout] if @params[:receive_timeout]

      begin
        # Ensure we have a valid token
        if @token.nil?
          log("No token available, getting new token...")
          @token = getToken()
        end

        request = Net::HTTP::Get.new(url)
        request["Authorization"] = "Bearer #{@token}"
        log("Making API request to: #{url} with token")

        response = https.request(request)

        log("API response code: #{response.code}")

        if response.code =~ /^4\d{2}$/
          log("Token expired (4xx HTTP response code), getting new token...")
          @token = getToken()
          request["Authorization"] = "Bearer #{@token}"
          response = https.request(request)
        end
      rescue Exception=>e
        log("Unable to authenticate to API: #{e}")
        if tries < max_tries
          tries = tries + 1
          log("#{tries}/#{max_tries}) Trying again...")
          sleep(2)
          retry
        end
        log("Failed to retrieve token for API calls.")
        return false
      end

      if response.code != '200'
        log("API response code #{response.code} != 200")
        log("API response body: #{response.body}")
        begin
          error_data = JSON.parse(response.body)
          raise "#{error_data['message'] || response.body}"
        rescue JSON::ParserError
          raise "HTTP #{response.code}: #{response.body}"
        end
      end

      # From Thycotic we are returned a rather large hash of all kinds of
      # data, but we really only want to return a few pieces. We dynamically
      # create a new Hash object here that looks like:
      #
      # hash = {
      #   "<secret field name>" = "<secret content>"
      #   "<secret field name>" = "<secret content>"
      #   "<secret field name>" = "<secret content>"
      # }
      #
      # In the event that any of the secret items returned are references to
      # files, we go off and get those files and put the contents of the file
      # into the hash.

      # Define the new Hash
      secret_hash = Hash.new
      log("getAndCacheSecretFromAPI() secret_hash:  #{secret_hash}")

      # Check if returned body is able to be parsed to JSON
      begin
        result = JSON.parse(response.body)
      rescue JSON::ParserError => e
        log("Error parsing request from API to JSON format")
        return false
      end

      # Grab the returned data. If its an array, fine. If its not an array,
      # wrap it in one just so the .each statement below works.
      secrets = result['items']

      unless secrets.kind_of?(Array)
        secrets = [secrets]
      end

      # Now for each element returned in the SecretItems XML section add
      # it to the above hash.
      secrets.each do |s|
        # Make sure the secret supplied has a field name... if not, then
        # its likely bogus data.
        if not s['fieldName'].nil?

          # In the event that we're looking at a File resource, we need to
          # download the file.
          if s['isFile'] == true
            if s['filename'] == ""
              content = ""
            else
              content = getFile(secretid, s['slug'])
              # log("secret file content: #{content}") # disabled to not leak secret content
            end
          else
            content = s['itemValue']
            # log("secret item value: #{content}") # disabled to not leak secret content
          end

          if @params[:sanitize_content] == true
            content = Utils.sanitize_content(content)
            # log("sanitized secret content: #{content}") # disabled to not leak secret content
          end

          # If the content is 'nil', then the secret cannot possibly have
          # held a value, so it must be bogus return data. Even an empty
          # secret will return a blank string.
          if not content.nil?
            log("Got secret content for Secret ID " \
                 "(#{secretid}/#{s['fieldName']})...\n")
            secret_hash[s['fieldName']] = content
          end
        end
      end
    rescue Exception =>e
      log("Error retrieving Secret ID #{secretid} from API service: #{e}")
      return false
    end

    # Attempt to save the secrets to our local cache. These methods do not
    # ever raise an exception. If they occationally fail, they swallow the
    # exception and move on.
    log("saving secret id #{secretid} to cache")
    saveSecretToCache(@cache,secretid,secret_hash)
    saveSecretToCache(@long_term_cache,secretid,secret_hash)

    # If we got here, we got the secret. Returning it
    # log("secret_hash: #{secret_hash}") # disabled to not leak secret content
    return secret_hash
  end

  def getFile(secretid, slug)
    # This method retreives file contents from the Secret Server with
    # the supplied Secret ID and FileID. This is meant to be used
    # as an internal method by the getSecret() method.
    #
    # * *Args*:
    #   - +secretid+ -> The secret ID that the file belongs to
    #   - +fileid+ -> The file ID to download
    #
    # * *Returns*:
    #   - String containing the ocntents of the downloaded file
    #
    # * *Raises*:
    #   - An exception if the File cannot be downloaded for some reason
    #     after 3 retries.
    #
    tries = 0
    max_tries = 3
    begin
      url = URI("#{@params[:serviceurl]}/api/v1/secrets/#{secretid}/fields/#{slug}")

      https = Net::HTTP.new(url.host, url.port)
      https.use_ssl = true
      https.verify_mode = eval(@params[:ssl_verify_mode]) if @params[:ssl_verify_mode]
      https.open_timeout = @params[:connect_timeout] if @params[:connect_timeout]
      https.read_timeout = @params[:receive_timeout] if @params[:receive_timeout]

      request = Net::HTTP::Get.new(url)
      request["Authorization"] = "Bearer #{@token}"

      response = https.request(request)

      # First find out if we errored out for any reason. If so, fail to
      # return a result and instead raise an exception.
      if response.code == '404'
        # There is no atual data to return, but this is not a bad thing. There simply is no
        # key... so return false.
        log("SecretItemId #{slug} empty, returning empty string.")
        return ''
      end

      if response.code != '200'
        log("Error retrieving SecretItemId #{slug}, Secret #{secretid}: " \
              "#{error}")
        raise "Error retrieving SecretItemId #{slug}, Secret #{secretid}: " \
              "#{error}"
      end

      log("SecretItemId #{slug} file retrieved...\n")
      return response.body
    rescue Exception=>e
      log("SecretItemId #{slug} retrieval failed: #{e}")
      if tries < max_tries
        tries = tries + 1
        log("(#{tries}/#{max_tries}) Trying again...")
        sleep(2)
        retry
      end

      # If we tried too many times, raise an exception.
      log("SecretItemId #{slug} retrieval failed too many times: #{e}")
      raise "SecretItemId #{slug} retrieval failed too many times: #{e}"
    end
  end

  # The following function will request a token from the oath endpoint of the pim API. This token will be used in the rest of the retrieval procedure of a secret.
  # initially it gets credentials and the API url from our thycotic.conf file.
  # This is then used to request the bearer token. If the return code of the request is 200, it returns the token, otherwise it raises an error that it was not able
  # to retrieve a token
  # We also set the @token value here as this is an instance var and will be used later on for easier use. We also add the token to the short term cache
  # This is so we don't always request a new token everytime we query pim
  def getToken()

    username = CGI.escape(@params[:username])
    password = CGI.escape(@params[:password])
    api_url  = @params[:serviceurl]

    url = URI("#{api_url}/oauth2/token")

    https = Net::HTTP.new(url.host, url.port)
    https.use_ssl = true
    https.verify_mode = eval(@params[:ssl_verify_mode]) if @params[:ssl_verify_mode]
    https.open_timeout = @params[:connect_timeout] if @params[:connect_timeout]
    https.read_timeout = @params[:receive_timeout] if @params[:receive_timeout]

    request = Net::HTTP::Post.new(url)
    request["Content-Type"] = "application/x-www-form-urlencoded"
    request.body = "username=#{username}&password=#{password}&grant_type=password"

    log("Making token request to: #{url}")
    log("Request body: #{request.body}")
    response = https.request(request)

    log("Token response code: #{response.code}")
    log("Token response body: #{response.body}")

    if response.code != '200'
      raise "Unable to retrieve authentication token: HTTP #{response.code} - #{response.body}"
    end

    result = JSON.parse(response.body)

    # Save the token to our local object to prevent getting it again
    @token = result["access_token"]

    # Before returning the token, cache it (if there is a local cache)
    if not @cache.nil?
      log("Saving token to cache...")
      @cache.set('rest_api_token', @token)
    end

    return result["access_token"]
  end
end

class Utils
  def self.sanitize_content(content)
    # Return only characters in the string which are not zero-width space
    #
    # * *Args*:
    #   - +content+ -> String content which are to be sanitized
    #
    return content.gsub(/[\u180e\u200b\u200f\ufeff]/, '')
  end
end
