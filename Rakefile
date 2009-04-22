# -*- ruby -*-

require 'rubygems'
require 'hoe'
require './lib/wilson.rb'

Hoe.new('wilson', Wilson::VERSION) do |p|
  p.rubyforge_name = 'seattlerb'
  p.developer('Ryan Davis', 'ryand-ruby@zenspider.com')
end

namespace :test do
  desc "profiles your tests"
  task :prof do
    send(*h.test_cmd(:zenprofile))
  end
end

# vim: syntax=Ruby
