# -*- ruby -*-

require 'rubygems'
require 'hoe'

Hoe.plugin :seattlerb

h = Hoe.spec 'wilson' do
  developer 'Ryan Davis', 'ryand-ruby@zenspider.com'

  self.rubyforge_name = 'seattlerb'

  multiruby_skip << '1.9'
end

namespace :test do
  desc "profiles your tests"
  task :prof do
    ruby "-S zenprofile #{h.make_test_cmd}"
  end
end

# vim: syntax=Ruby
