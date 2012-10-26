=====================================
Puppet Plugin: Thycotic Secret Getter
=====================================

This Puppet plugin allows you to access `secrets` from the Thycotic Secret Server
(either Online edition, or your own in-house hosted edition) from within your
Puppet manifests.


Description
-----------

By allowing you to reference passwords, certificates and other private data from
within your Puppet manifests, but not actually storing that private data within
them, your puppet code becomes readable by a wider audience of team members, and
more secure.

By example, rather than code that says ::

    file { '/etc/mypassword':
      content => 'SillyPassword';
    }

you can obscure the contents of your password by storing them in the Thycotic
Secret Server and accessing them like this ::

    file { '/etc/mypassword':
      content => thycotic_getsecret('12345','plaintext_password');
    }

Under the hood
--------------

The `thycotic_getsecret` function leverages the `Thycotic` ruby class to make
API calls against the Thycotic secret server. On your Puppet server, a private
configuration file provides the credentials that this plugin uses to access
`The Secret Server.` Once a `secret` has been downloaded once, it is cached in
both a short-term and a long-term cache.

The short-term cache is used for performance, as well as to limit the number
of API calls made to `The Secret Server` API service. It has a configurable
expiration time.

The long-term cache is used as a fail-safe in case the API service goes offline
for a long period of time. It is only used in the event that the remote API
service is entirely unavailable.

Installation and Configuration
------------------------------
Installation is simple... checkout this Git repository into a new module in your
Puppet modules path, and create the configuration file ::

    cd <your puppet path>/modules
    git clone git@github.com:Nextdoor/puppet_thycotic.git

Create the configuration file `/etc/puppet/thycotic.conf` ::

    url = https://www.secretserveronline.com/webservices/SSWebService.asmx
    user = username
    password = pwd
    orgcode = orgCodd

Usage
-----

    file { '/etc/mypassword':
      content => thycotic_getsecret('12345','plaintext_password');
    }
