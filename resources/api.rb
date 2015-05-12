#
# CohesiveFT VPN-Cubed Administration API
# Ruby client library
# http://cohesiveft.com/vpncubed
#
# Copyright (c) 2010-2012, Cohesive Flexible Technologies, Inc.
#
# This copyrighted material is the property of
# Cohesive Flexible Technologies and is subject to the license
# terms of the product it is contained within, whether in text
# or compiled form.  It is licensed under the terms expressed
# in the accompanying README and LICENSE files.
#
# This program is AS IS and  WITHOUT ANY WARRANTY; without even
# the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.

require 'rubygems'
require 'net/https'
require 'json'
require 'cgi'
require 'openssl'

module VPNCubed
  module API

    class APIError < StandardError; end
    class AuthorizationError < APIError; end
    class BadRequestError < APIError; end
    class RequestDeniedError < APIError; end
    class InternalServerError < APIError; end
    class ConnectionError < APIError; end

    URI_PREFIX = '/api/'

    METHODS = {
      # auth
      :reset_password => {
                    :uri => 'api_password', :verb => :put,
                    :args => { :password => :string } },

      # status
      :desc_status => {
                    :uri => 'status', :verb => :get },
      :desc_ipsec_status => {
                    :uri => 'status/ipsec', :verb => :get },
      :desc_clients_status => {
                    :uri => 'status/clients', :verb => :get },
      :desc_system_status => {
                    :uri => 'status/system', :verb => :get,
                    :args => { :timestamp => [ :integer, nil ] } },
      :desc_link_history => {
                    :uri => 'status/link_history', :verb => :get,
                    :args => { :remote => [ :string, nil ],
                               :local => [ :string, nil ],
                               :tunnelid => [ :integer, nil ] } },
      :desc_connected_subnets => {
                    :uri => 'status/connected_subnets', :verb => :get,
                    :args => { :extended_output => [ :boolean, false ] } },

      # licensing
      :desc_license => {
                    :uri => 'license', :verb => :get },
      :upload_license => {
                    :uri => 'license', :verb => :put,
                    :args => { :license => :blob },
                    :request_content_type => 'text/plain' },
      :upgrade_license => {
                    :uri => 'license/upgrade', :verb => :put,
                    :args => { :license => :blob },
                    :request_content_type => 'text/plain' },
      :set_license_parameters => {
                 :uri => 'license/parameters', :verb => :put,
                 :args => { :default => [ :boolean, false ],
                            :subnet => [ :string, nil ],
                            :managers => [ :string, nil ],
                            :clients => [ :string, nil ],
                            :my_manager_vip => [ :string, nil ] } },

      # manager configuration
      :desc_config => {
                    :uri => 'config', :verb => :get },
      :edit_config => {
                    :uri => 'config', :verb => :put,
                    :args => { :topology_name => [ :string, nil ] } },

      # keyset
      :desc_keyset => {
                    :uri => 'keyset', :verb => :get },
      :setup_keyset => {
                    :uri => 'keyset', :verb => :put,
                    :args => { :source => [ :string, "" ],
                               :token => [ :string, "" ],
                               :topology_name => [ :string, nil ] } },

      # peering
      :desc_peering => {
                    :uri => 'peering', :verb => :get },
      :set_manager_id => {
                    :uri => 'peering/self', :verb => :put,
                    :args => { :id => :integer } },
      :add_peer => {
                    :uri => 'peering/peers', :verb => :post,
                    :args => { :id => :integer, :name => :string } },
      :edit_peer => {
                    :uri => 'peering/peers/:id', :verb => :put,
                    :args => { :id => :integer, :name => :string } },
      :delete_peer => {
                    :uri => 'peering/peers/:id', :verb => :delete,
                    :args => { :id => :integer } },

      # routes
      :desc_routes => {
                    :uri => 'routes', :verb => :get },
      :add_route => {
                    :uri => 'routes', :verb => :post,
                    :args => { :cidr => :string } },
      :delete_route => {
                    :uri => 'routes/:id', :verb => :delete,
                    :args => { :id => :string } },

      # clientpacks
      :desc_clientpacks => {
                    :uri => "clientpacks", :verb => :get,
                    :args => { :sorted => [ :boolean, false ] } },
      :fetch_clientpack => {
                    :uri => 'clientpack', :verb => :get,
                    :response_content_type => '*/*', :binary_response => true,
                    :args => { :name => :string,
                               :format => [ :string, 'tarball' ] } },
      :get_next_available_clientpack => {
                    :uri => 'clientpacks/next_available', :verb => :post },
      :edit_clientpack => {
                    :uri => 'clientpack', :verb => :put,
                    :args => { :name => :string,
                               :enabled => [ :boolean, nil ],
                               :checked_out => [ :boolean, nil ] } },
      # disconnect_clientpack is marked for deprecation in the future -
      # use reset_clientpack instead
      :disconnect_clientpack => {
                    :uri => 'clientpack/:name', :verb => :put,
                    :marked_for_deprecation => true,
                    :args => { :name => :string,
                               :disconnect => [ :boolean, true ] } },

      # clients (also see desc_clients_status above)
      :reset_client => {
                    :uri => 'client/reset', :verb => :post,
                    :args => { :name => :string } },
      :reset_all_clients => {
                    :uri => 'clients/reset_all', :verb => :post },

      # snapshots
      :desc_snapshots => {
                    :uri => 'snapshots', :verb => :get },
      :create_snapshot => {
                    :uri => 'snapshots', :verb => :post },
      :delete_snapshot => {
                    :uri => 'snapshots/:name', :verb => :delete,
                    :args => { :name => :string } },
      :import_snapshot => {
                    :uri => 'snapshots/running_config', :verb => :put,
                    :args => { :snapshot => :blob },
                    :request_content_type => 'application/octet-stream' },
      :fetch_snapshot => {
                    :uri => 'snapshots/:name', :verb => :get,
                    :args => { :name => :string },
                    :response_content_type => '*/*',
                    :binary_response => true },

      # ipsec
      :desc_ipsec => {
                    :uri => 'ipsec', :verb => :get },
      :setup_ipsec => {
                    :uri => 'ipsec', :verb => :post,
                    :args => { :restart => :boolean } },
      :edit_ipsec_config => {
                    :uri => 'ipsec', :verb => :put,
                    :args => { :ipsec_local_ipaddress => [ :ipaddress, nil ],
                               :nat_traversal => [ :boolean, nil ] } },
      # get_ipsec_local_ipaddress is marked for deprecation
      # in the future - use desc_ipsec instead
      :get_ipsec_local_ipaddress => {
                    :uri => 'ipsec/local_ipaddress', :verb => :get,
                    :marked_for_deprecation => true },
      # set_ipsec_local_ipaddress is marked for deprecation
      # in the future - use edit_ipsec_config instead
      :set_ipsec_local_ipaddress => {
                    :uri => 'ipsec/local_ipaddress', :verb => :put,
                    :args => { :ipaddress => :ipaddress },
                    :marked_for_deprecation => true },
      :create_ipsec_endpoint => {
                    :uri => 'ipsec/endpoints', :verb => :post,
                    :args => { :name => :string, :ipaddress => :ipaddress,
                    :secret => :string, :pfs => [ :boolean, true ],
                    :extra_config => [ :string, nil ],
                    :private_ipaddress => [ :ipaddress, nil ] } },
      # note - to unset private_ipaddress, pass "0.0.0.0" as its value
      :edit_ipsec_endpoint => {
                    :uri => 'ipsec/endpoints/:endpoint', :verb => :put,
                    :args => { :endpoint => :string,
                    :ipaddress => [ :ipaddress, nil ],
                    :secret => [ :string, nil ],
                    :private_ipaddress => [ :ipaddress, nil ],
                    :pfs => [ :boolean, nil ],
                    :extra_config => [ :string, nil ] } },
      :delete_ipsec_endpoint => {
                    :uri => 'ipsec/endpoints/:endpoint', :verb => :delete,
                    :args => { :endpoint => :string } },
      :desc_ipsec_endpoint => {
                    :uri => 'ipsec/endpoints/:endpoint', :verb => :get,
                    :args => { :endpoint => :string } },
      :create_ipsec_tunnel => {
                    :uri => 'ipsec/endpoints/:endpoint/tunnels',
                    :verb => :post,
                    :args => { :endpoint => :string,
                               :remote_subnet => :string,
                               :local_subnet => [ :string, nil ],
                               :ping_ipaddress => [ :ipaddress, nil ],
                               :ping_interval => [ :integer, nil ],
                               :description => [ :string, nil ] } },
      :edit_ipsec_tunnel => {
                    :uri => 'ipsec/endpoints/:endpoint/tunnels/:tunnelid',
                    :verb => :put,
                    :args => { :endpoint => :string, :tunnelid => :integer,
                               :bounce => [ :boolean, false ],
                               :description => [ :string, nil ],
                               :ping_ipaddress => [ :ipaddress, nil ],
                               :ping_interval => [ :integer, nil ] } },
      :delete_ipsec_tunnel => {
                    :uri => 'ipsec/endpoints/:endpoint/subnets/:tunnelid',
                    :verb => :delete,
                    :args => { :endpoint => :string,
                               :tunnelid => :integer } },
      :create_ebgp_peer => {
                    :uri => 'ipsec/endpoints/:endpoint/ebgp_peers',
                    :verb => :post,
                    :args => { :endpoint => :string,
                               :ipaddress => :ipaddress, :asn => :integer } },
      :delete_ebgp_peer => {
                 :uri => 'ipsec/endpoints/:endpoint/ebgp_peers/:ebgppeerid',
                 :verb => :delete,
                 :args => { :endpoint => :string,
                            :ebgppeerid => :integer } },

      # firewall
      :desc_firewall => {
                :uri => 'firewall/rules', :verb => :get },
      :add_firewall_rule => {
                :uri => 'firewall/rules', :verb => :post,
                :args => { :rule => :string, :position => [ :integer, -1 ] } },
      :delete_firewall_rule => {
                :uri => 'firewall/rules/:position', :verb => :delete,
                :args => { :position => :integer } },

      # admin
      :setup_remote_support => {
                :uri => 'remote_support', :verb => :put,
                :args => { :enabled => :boolean } },
      :generate_remote_support_keypair => {
                :uri => 'remote_support/keypair', :verb => :post,
                :args => { :encrypted_passphrase => :blob },
                :request_content_type => 'text/plain',
                :binary_response => true,
                :response_content_type => '*/*' },
      :setup_admin_ui => {
                :uri => 'admin_ui', :verb => :put,
                :args => { :enabled => [ :boolean, nil ],
                           :username => [ :string, nil ],
                           :password => [ :string, nil ] } },
      :server_action => {
                :uri => 'server', :verb => :put,
                :args => { :reboot => [ :boolean, nil ] } }

    }

    def self.blob_args
      METHODS.values.reject { |v| v[:args].nil?
        }.map { |v| v[:args].keys.select { |k| v[:args][k] == :blob }
        }.flatten.uniq
    end

    def self.api_methods
      METHODS.keys
    end

    def self.describe_api_method(meth)
      return nil unless METHODS[meth.to_sym]
      h = {}.merge METHODS[meth.to_sym]
      h[:uri] = "#{URI_PREFIX}#{h[:uri]}"
      h
    end

    class Connection

      attr_reader :error, :raw_response
      attr_accessor :host, :port, :key, :secret, :timeout, :lax_https_check

      def initialize(host, args={})
        @host = host
        @port = args[:port] || 8000
        @key = args[:key]
        @secret = args[:secret]
        @timeout = args[:timeout] || 10.0
        @lax_https_check = args[:lax_https_check]
      end

      def method_missing(meth, args={}, &blk)
        if VPNCubed::API.api_methods.include? meth
          send_request(meth, VPNCubed::API.describe_api_method(meth), args)
        else
          super
        end
      end

      def close
        @https = nil
      end

      alias :reset :close

      # inspired by wait_for in
      # http://github.com/geemus/fog/blob/master/lib/fog/model.rb
      def wait_for(options={}, &blk)
        timeout = options[:timeout] || 0  # wait forever by default
        delay = options[:delay] || 1
        started = Time.now
        loop do
          begin
            break if instance_eval(&blk)
          rescue Timeout::Error, APIError
            :ignore
          end
          raise Timeout::Error if timeout > 0 && Time.now > started + timeout
          puts("wait_for(#{host}): still waiting - " +
               "#{(Time.now - started).to_i}s") if options[:verbose]
          sleep delay
        end
      end

      private

      def raise_error(name, message)
        @error = { "name" => name.to_s, "message" => message.to_s }
        raise APIError, message
      end

      def https
        return @https if @https && @https.active?

        @https = Net::HTTP.new(@host, @port)
        @https.open_timeout = @timeout
        @https.read_timeout = @timeout
        @https.use_ssl = true
        @https.ssl_timeout = @timeout
        @https.verify_mode = OpenSSL::SSL::VERIFY_NONE
        
        unless @lax_https_check
          @https.start
          if @https.peer_cert.subject.to_s !~ /OU=CohesiveFT_VPNCubed/
            raise_error :ConnectionError, 
              "Server presented bad SSL cert (not VPN-Cubed)"
          end
        end

        @https
      end

      def send_request(meth, meth_def, args)
        # catch Timeout::Error here and let caller see it as APIError
        # or let Timeout::Error go to caller? FIXME TODO
        req = make_request(meth, meth_def, args)
        if meth_def[:marked_for_deprecation]
          warn "method #{meth} has been marked for deprecation in the future"
        end
        retries = 1
        begin
          if retries >= 0
            retries -= 1
            resp = https.request(req)
          else
            raise_error :ConnectionError, "Connection error"
          end
        rescue APIError
          raise
        rescue Timeout::Error, StandardError
          reset
          retry
        end

        @raw_response = resp

        @error = nil
        case resp
          when Net::HTTPOK, Net::HTTPCreated
            # HTTP 200 OK, HTTP 201 Created
            if meth_def[:binary_response]
              return resp.body
            else
              return JSON.parse(resp.body)["response"]
            end
          when Net::HTTPUnauthorized
            # HTTP 401 Unauthorized
            raise AuthorizationError
        end

        @error = JSON.parse(resp.body)["error"] rescue nil
        case resp
          when Net::HTTPBadRequest
            # HTTP 400 Bad Request
            # "The client SHOULD NOT repeat the request without
            # modifications."
            # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
            raise BadRequestError
          when Net::HTTPForbidden
            # HTTP 403 Forbidden
            # "The server understood the request, but is refusing
            # to fulfill it."
            # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
            raise RequestDeniedError
          when Net::HTTPInternalServerError
            # HTTP 500 Internal Server Error
            raise InternalServerError
          else
            raise APIError, resp.inspect
        end
      end

      def make_request(meth, meth_def, args)
        verb = meth_def[:verb]
        uri = meth_def[:uri]

        params = { }
        blob_method = false
        if meth_def[:args].nil?
          raise(BadRequestError, "unexpected arguments") if args.any?
        else
          meth_def[:args].each_pair do |key, val|
            unset_param_if_not_set = false
            if val.is_a? Array
              type, default_value = val
              unset_param_if_not_set = default_value.nil?
            else
              type, default_value = val, nil
            end
            blob_method ||= type == :blob

            params[key] = args[key.to_s] || args[key]
            if params[key].nil?
              if unset_param_if_not_set
                params.delete key
              elsif default_value.nil?
                raise(BadRequestError, "required argument not set: #{key}")
              else
                params[key] = default_value
              end
            else
              args.delete key.to_s
              args.delete key
              # TODO: add client-side validation here?
            end
          end
        end

        if args.any?
          raise BadRequestError, "unexpected arguments after parsing"
        end

        params.keys.each { |key|
          if uri.include? "/:#{key}"
            uri.gsub! "/:#{key}", "/#{params[key]}"
            params.delete key
          end
        }

        request_content_type = meth_def[:request_content_type] ||
          'application/json'
        response_content_type = meth_def[:response_content_type] ||
          'application/json'

        case verb
          when :get
            if params.any?
              uri += "?"
              params.each_pair { |k, v| uri += "#{k}=#{CGI::escape(v.to_s)}&" }
              uri.gsub! /&$/, ''
            end
            req = Net::HTTP::Get.new(uri)
          when :post, :put
            req = Net::HTTP.const_get(verb.to_s.capitalize).new(uri)
            if params.any?
              if blob_method
                req.body = params.values.first
              else
                req.body = params.to_json
              end
              req.add_field 'Content-Type', request_content_type
            end
          when :delete
            req = Net::HTTP::Delete.new(uri)
        end

        req.add_field 'Accept', response_content_type
        req.basic_auth(@key, @secret)
        req
      end

    end
  end
   
end


