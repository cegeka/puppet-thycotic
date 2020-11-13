Puppet::Functions.create_function(:thycotic_lookup_secret) do
  require 'parseconfig'
  require 'rubygems'
  require File.join(File.dirname(__FILE__), 'thycotic.rb')

  $last_thycotic_config_file = nil

  dispatch :thycotic_lookup_secret do
    param 'String[1]', :key
    param 'Hash[String[1],Any]', :options
    param 'Puppet::LookupContext', :context
  end

  def init(custom_config = nil)
    # Initializes the configuration for this function. In order to avoid
    # constantly creating new Thycotic API access objects, we store one
    # globally once we've created it.
    #
    # * *Returns*:
    #   A Thycotic object that has been fully configured
    #

    # By default, this method looks for the thycotic.conf file in the following
    # filesystem locations:
    #
    #   /etc/puppet/thycotic.conf
    #   <local path to this file>/thycotic.conf
    #
    # However, if a custom_config file parameter is supplied, then we use that
    # file instead.
    possible_paths = [
      "#{Facter.value('thycotic_configpath')}/thycotic.conf",
      '/etc/puppetlabs/puppet/thycotic.conf',
      '/etc/puppet/thycotic.conf',
      File.join(File.dirname(__FILE__), 'thycotic.conf')
    ]

    possible_paths = custom_config unless custom_config.nil?

    possible_paths.each do |p|
      begin
        @cfg_file = ParseConfig.new(p)
        $last_thycotic_config_file = p
        break
      rescue Exception => e
        # Just move on.. We will catch the error with a check below
      end
    end

    # Was the config file even loaded?
    if @cfg_file.nil?
      raise Puppet::ParseError, 'Could not load configuration. Please see ' \
          "README. Supplied config paths: #{p}."
    end

    # Check for the config file and pull the variables that were supplied.
    begin
      config = {
        username: @cfg_file['username'],
        password: @cfg_file['password'],
        orgcode: @cfg_file['orgcode']
      }
      rescue Exception => e
        raise Puppet::ParseError, "Missing configuration options in thycotic.conf: #{e}"
      end

      # Now look for optional variables. If they're found, use them. If not, use
      # some defaults
      config[:serviceurl] = @cfg_file['wsdl'] unless @cfg_file['wsdl'].nil?
      config[:cache_path] = @cfg_file['cache_path'] unless @cfg_file['cache_path'].nil?
      config[:cache_owner] = @cfg_file['cache_owner'] unless @cfg_file['cache_owner'].nil?
      config[:cache_group] = @cfg_file['cache_group'] unless @cfg_file['cache_group'].nil?
      config[:domain] = @cfg_file['domain'] unless @cfg_file['domain'].nil?
      config[:debug] = true if @cfg_file['debug'] == 'true'
      config[:connect_timeout] = @cfg_file['connect_timeout'] unless @cfg_file['connect_timeout'].nil?
      config[:send_timeout] = @cfg_file['send_timeout'] unless @cfg_file['send_timeout'].nil?
      config[:receive_timeout] = @cfg_file['receive_timeout'] unless @cfg_file['receive_timeout'].nil?
      config[:ssl_verify_mode] = @cfg_file['ssl_verify_mode']
      config[:sanitize_content] = @cfg_file['sanitize_content'] unless @cfg_file['sanitize_content'].nil?

      # Create the Thycotic API object
      Thycotic.new(config)
  end

  # The main function, this will fetch the secret
  def thycotic_lookup_secret(key, options, context)
    # We're only interested in keys that match with 'thycotic::lookup::<secret_id>::<field_name>'
    regexp = Regexp.new(/thycotic::lookup::(?<secretid>[0-9]+)::(?<fieldname>[a-zA-Z0-9]+)/)

    if !key.match(regexp)
      context.not_found
    end
    
    # Extract the fields we're interested in
    secret_id, secret_name = key.match(regexp).captures

    # Create our Thycotic object if it doesn't already exist
    # Look for our config file in a few locations (in order):
    begin
      @thycotic ||= init()
    rescue Exception => e
      raise Puppet::ParseError, "Could not initialize Thycotic object: #{e}"
    end

    # Now request our secret
    Puppet.debug "#{Facter.value('fqdn')} requested #{secret_id}"
    secret = @thycotic.getSecret(secret_id)

    # Walk through the returned elements of the hash, and look for the one we want.
    if secret.key?(secret_name)
      if secret.key?(secret_name).nil?
        raise Puppet::ParseError, "Secret returned by Thycotic.getSecret(#{secret_id}) was 'nil'. This is bad, erroring out."
      else
        return secret[secret_name].to_s
      end
    end

    raise Puppet::ParseError, "Could not retrieve SecretID #{secret_id}."
  end
end
