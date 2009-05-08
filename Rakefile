# -*- ruby -*-

require 'rubygems'
require 'hoe'
require './lib/wilson.rb'

h = Hoe.new('wilson', Wilson::VERSION) do |p|
  p.rubyforge_name = 'seattlerb'
  p.developer('Ryan Davis', 'ryand-ruby@zenspider.com')
end

namespace :test do
  desc "profiles your tests"
  task :prof do
    ruby "-S zenprofile #{h.make_test_cmd}"
  end
end

# vim: syntax=Ruby
