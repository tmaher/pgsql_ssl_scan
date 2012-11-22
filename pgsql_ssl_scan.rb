#!/usr/bin/env ruby

require "rubygems"
require "bundler/setup"

require "openssl"
require "socket"

def my_ctx my_cipher
  ctx = OpenSSL::SSL::SSLContext.new(:TLSv1)
  puts "trying #{my_cipher}"
  ctx.ciphers = my_cipher
  ctx
end

def pgpsql_test test_host, test_port
  # http://www.postgresql.org/docs/8.3/static/protocol-flow.html#AEN73982
  # u8 ssl_request[8]={0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f};
  magic = [0, 0, 0, 8, 0x4, 0xd2, 0x16, 0x2f].pack "CCCCCCCC"

  supported = []
  tried = []
  `openssl ciphers`.split(":").each do |c|
    c.upcase!
    next if tried.include? c
    tried.push c
    bare_sock = TCPSocket.new(test_host, test_port)
    bare_sock.write magic
    bare_sock.read 1

    begin
      sock = OpenSSL::SSL::SSLSocket.new bare_sock, my_ctx(c)
    rescue OpenSSL::SSL::SSLError => e
      bare_sock.close
      next
    end
    begin
      sock.connect
      supported.push(sock.cipher[0])
    rescue OpenSSL::SSL::SSLError => e
    end
    sock.close
  end

  puts "supported: #{supported}"
end

pgpsql_test ARGV[0], ARGV[1]
