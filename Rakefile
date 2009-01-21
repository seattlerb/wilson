# -*- ruby -*-

require 'rubygems'
require 'hoe'
require './lib/metal.rb'

h=Hoe.new('metal', Metal::VERSION) do |p|
  p.rubyforge_name = 'seattlerb'
  p.developer('Ryan Davis', 'ryand-ruby@zenspider.com')
end

class Hoe
  def test_cmd flavor = nil
    msg = flavor ? :sh : :ruby
    tests = ["rubygems", self.testlib] +
      test_globs.map { |g| Dir.glob(g) }.flatten
    tests.map! {|f| %Q(require "#{f}")}
    cmd = "#{RUBY_FLAGS} -e '#{tests.join("; ")}' #{FILTER}"

    ENV['EXCLUDED_VERSIONS'] = multiruby_skip.join(":")

    cmd = "#{flavor} #{cmd}" if flavor

    return msg, cmd
  end
end

# def run_tests(multi=false) # :nodoc:
#   msg = multi ? :sh : :ruby
#   cmd = if test ?f, 'test/test_all.rb' then
#           "#{RUBY_FLAGS} test/test_all.rb #{FILTER}"
#         else
#           tests = ["rubygems", self.testlib] +
#             test_globs.map { |g| Dir.glob(g) }.flatten
#           tests.map! {|f| %Q(require "#{f}")}
#           "#{RUBY_FLAGS} -e '#{tests.join("; ")}' #{FILTER}"
#         end
#
#   excludes = multiruby_skip.join(":")
#   ENV['EXCLUDED_VERSIONS'] = excludes
#   cmd = "multiruby #{cmd}" if multi
#
#   send msg, cmd
# end


namespace :test do
  desc "profiles your tests"
  task :prof do
    send(*h.test_cmd(:zenprofile))
  end

  desc "rcov your tests"
  task :rcov do
    raise "not yet"
  end
end

begin
  require 'rcov/rcovtask'
  Rcov::RcovTask.new do |t|
    pattern = ENV['PATTERN'] || 'test/test_*.rb'

    t.test_files = FileList[pattern]
    t.verbose = true
    t.rcov_opts << "--threshold 80"
    t.rcov_opts << "--no-color"
  end
rescue LoadError
  # skip
end
# vim: syntax=Ruby
