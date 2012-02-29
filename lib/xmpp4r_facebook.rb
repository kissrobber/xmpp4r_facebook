#coding:utf-8
require 'xmpp4r'

module Jabber
  module SASL
    class XFacebookPlatform < Base
      def initialize(stream, api_key, access_token, secret_key)
        super(stream)
        challenge = {}
        error = nil
        @stream.send(generate_auth('X-FACEBOOK-PLATFORM')) { |reply|
          if reply.name == 'challenge' and reply.namespace == NS_SASL
            challenge = decode_challenge(reply.text)
          else
            error = reply.first_element(nil).name
          end
          true
        }
        raise error if error
        
        @nonce = challenge['nonce']
        @realm = challenge['realm']
        @method = challenge['method']
        @api_key = api_key
        @access_token = access_token
        @secret_key = secret_key
      end
      
      def decode_challenge(challenge)
        text = Base64::decode64(challenge)
        res = {}
        state = :key
        key = ''
        value = ''
        text.scan(/./) do |ch|
          if state == :key
            if ch == '='
              state = :value
            else
            key += ch
            end
          elsif state == :value
            if ch == '&'
              # due to our home-made parsing of the challenge, the key could have
              # leading whitespace. strip it, or that would break jabberd2 support.
              key = key.strip
              res[key] = value
              key = ''
              value = ''
              state = :key
            elsif ch == '"' and value == ''
              state = :quote
            else
            value += ch
            end
          elsif state == :quote
            if ch == '"'
              state = :value
            else
            value += ch
            end
          end
        end
        # due to our home-made parsing of the challenge, the key could have
        # leading whitespace. strip it, or that would break jabberd2 support.
        key = key.strip
        res[key] = value unless key == ''
        Jabber::debuglog("SASL DIGEST-MD5 challenge:\n#{text}\n#{res.inspect}")
        res
      end
      
      ##
      # * Send a response
      # * Wait for the server's challenge (which aren't checked)
      # * Send a blind response to the server's challenge
      def auth(password)
        response2 = {}
        response2['api_key'] = @api_key
        response2['call_id'] = Time.new.tv_sec
        response2['method'] = @method
        response2['nonce'] = @nonce
        response2['access_token'] = @access_token
        response2['v'] ='1.0'
        
        response_text = response2.collect { |k,v| "#{k}=#{v}" }.join('&')
        #Jabber::debuglog("SASL DIGEST-MD5 response:\n#{response_text}\n#{response.inspect}")
        
        r = REXML::Element.new('response')
        r.add_namespace NS_SASL
        r.text = Base64::encode64(response_text)
        success_already = false
        error = nil
        @stream.send(r) { |reply|
          if reply.name == 'success'
          success_already = true
          elsif reply.name != 'challenge'
            error = reply.first_element(nil).name
          end
          true
        }
        
        return if success_already
        raise error if error
        
        # TODO: check the challenge from the server
        
        r.text = nil
        @stream.send(r) { |reply|
          if reply.name != 'success'
            error = reply.first_element(nil).name
          end
          true
        }
        
        raise error if error
      end
      
      private
      
      ##
      # Function from RFC2831
      def h(s); Digest::MD5.digest(s); end
      
      ##
      # Function from RFC2831
      def hh(s); Digest::MD5.hexdigest(s); end
      
      ##
      # Calculate the value for the response field
      def response_value(username, realm, digest_uri, passwd, nonce, cnonce, qop, authzid)
        a1_h = h("#{username}:#{realm}:#{passwd}")
        a1 = "#{a1_h}:#{nonce}:#{cnonce}"
        if authzid
          a1 += ":#{authzid}"
        end
        if qop == 'auth-int' || qop == 'auth-conf'
          a2 = "AUTHENTICATE:#{digest_uri}:00000000000000000000000000000000"
        else
          a2 = "AUTHENTICATE:#{digest_uri}"
        end
        hh("#{hh(a1)}:#{nonce}:00000001:#{cnonce}:#{qop}:#{hh(a2)}")
      end
    end
  end
end