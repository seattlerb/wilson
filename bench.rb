#!/usr/bin/ruby -w

# % rm -r ~/.ruby_inline; ./bench.rb 1_000_000 1_000
# # of iterations = 1000000
# $n = 1000
#
#                           user     system      total        real
# null_time             0.120000   0.000000   0.120000 (  0.122507)
# cee_nil               0.280000   0.000000   0.280000 (  0.279552)
# asm_nil               0.280000   0.000000   0.280000 (  0.275498)
# ruby_nil              0.370000   0.000000   0.370000 (  0.372142)
# cee                   0.830000   0.010000   0.840000 (  0.837607)
# asm2                  0.830000   0.000000   0.830000 (  0.839430)
# asm                   3.520000   0.000000   3.520000 (  3.542521)
# ruby                 98.970000   0.430000  99.400000 (101.903256)
#
# % rm -r ~/.ruby_inline; ./bench.rb 10_000_000 100
# # of iterations = 10000000
# $n = 100
#
#                           user     system      total        real
# null_time             1.220000   0.000000   1.220000 (  1.243087)
# cee_nil               2.780000   0.010000   2.790000 (  2.825447)
# asm_nil               2.760000   0.010000   2.770000 (  2.770936)
# ruby_nil              3.710000   0.000000   3.710000 (  3.735188)
# cee                   3.560000   0.010000   3.570000 (  3.581262)
# asm2                  3.450000   0.010000   3.460000 (  3.481769)
# asm                   5.990000   0.010000   6.000000 (  6.042270)
# ruby                 95.460000   0.300000  95.760000 ( 96.578792)

$: << 'lib'
require 'wilson'
require 'rubygems'
require 'inline'
require 'benchmark'

max = (ARGV.shift || 10_000_000).to_i
n   = (ARGV.shift || 100).to_i

class Counter
  inline do |builder|
    builder.c "VALUE cee_nil() { return Qnil;}"
    builder.c "long cee(int n) { long i; for (i = 0;i<n+1;i++) {}; return i;}"
  end

  defasm :asm_nil do
    eax.mov 4
  end

  defasm :asm, :n do # naive version
    eax.xor eax

    ecx.mov arg(0)
    from_ruby ecx
    ecx.inc

    count = self.label
    eax.inc
    count.loop

    to_ruby eax
  end

  defasm :asm2, :n do
    eax.xor eax

    edx.mov arg(0)
    from_ruby edx
    edx.inc

    count = self.label
    eax.inc
    eax.cmp edx
    jnz count

    to_ruby eax
  end

  def ruby_nil
    nil
  end

  def ruby n
    (n+1).times do; end
  end
end

counter = Counter.new

%w(cee_nil asm_nil ruby_nil).each do |name|
  eval "abort 'bad #{name}' unless counter.#{name}.nil? "
end

%w(cee asm2 asm ruby).each do |name|
  eval "
    x = counter.#{name}(n)
    warn \"%5s = %4d\" % [name, x] if $DEBUG
    abort 'bad #{name}' unless x == n + 1
  "
end

exit 0 if $DEBUG

puts "# of iterations = #{max}"
puts "n = #{n}"
puts
Benchmark::bm(20) do |x|
  x.report("null_time") do
    for i in 0..max do
      # do nothing
    end
  end

  %w(cee_nil asm_nil ruby_nil).each do |name|
    eval "
      x.report(#{name.inspect}) do
        for i in 0..max do
          counter.#{name}
        end
      end
    "
  end

  funcs = %w(cee asm2 asm)
  funcs << 'ruby' if ENV['PAIN']
  funcs.each do |name|
    eval "
      x.report(#{name.inspect}) do
        for i in 0..max do
          counter.#{name}(n)
        end
      end
    "
  end
end
