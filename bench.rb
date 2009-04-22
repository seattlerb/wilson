#!/usr/bin/ruby -w

# % rm -r ~/.ruby_inline; ./bench.rb 1_000_000 1_000
# # of iterations = 1000000
#                           user     system      total        real
# null_time             0.130000   0.000000   0.130000 (  0.123534)
# c-nil                 0.280000   0.000000   0.280000 (  0.284030)
# asm-nil               0.270000   0.000000   0.270000 (  0.278700)
# c                     0.830000   0.010000   0.840000 (  0.841285)
# asm2                  0.840000   0.000000   0.840000 (  0.842834)
# asm                   3.510000   0.010000   3.520000 (  3.543986)
# ruby                 89.790000   0.200000  89.990000 ( 90.653678)

$: << 'lib'
require 'wilson'
require 'rubygems'
require 'inline'
require 'benchmark'

max = (ARGV.shift || 10_000_000).to_i
$n  = (ARGV.shift || 10).to_i

class Counter
  inline do |builder|
    builder.c "VALUE cee_nil() { return Qnil;}"
    builder.c "long cee() { long i; for (i = 0;i<#{$n};i++) {}; return i;}"
  end

  # 00000f7a  pushl %ebp
  # 00000f7b  xorl  %eax,%eax
  # 00000f7d  movl  %esp,%ebp
  # 00000f7f  incl  %eax
  # 00000f80  cmpl  $0x000003e8,%eax
  # 00000f85  jne 0x00000f7f
  # 00000f87  leave
  # 00000f88  movw  $0x07d1,%ax
  # 00000f8c  ret

  defasm :asm_nil do
    eax.mov 4
  end

  defasm :asm do
    eax.mov 0
    ecx.mov $n
    count = self.label
    eax.add 1
    count.loop

    eax.add eax # fixnum: n + n + 1
    eax.inc
  end

  # 00000000  55                push ebp
  # 00000001  89E5              mov ebp,esp
  # 00000003  56                push esi
  # 00000004  57                push edi
  # 00000005  B800000000        mov eax,0x0
  # 0000000A  B910270000        mov ecx,0x2710
  # 0000000F  83C001            add eax,byte +0x1
  # 00000012  E2FB              loop 0xf
  # 00000014  01C0              add eax,eax
  # 00000016  40                inc eax
  # 00000017  5F                pop edi
  # 00000018  5E                pop esi
  # 00000019  C9                leave
  # 0000001A  C3                ret

  defasm :asm2 do
    eax.mov 0
    count = self.label
    eax.inc
    eax.cmp $n
    jne count

    eax.add eax # fixnum: n + n + 1
    eax.inc
  end

  # 00000000  55                push ebp
  # 00000001  89E5              mov ebp,esp
  # 00000003  B800000000        mov eax,0x0
  # 00000008  40                inc eax
  # 00000009  3DE8030000        cmp eax,0x3e8
  # 0000000E  75F8              jnz 0x8
  # 00000010  01C0              add eax,eax
  # 00000012  40                inc eax
  # 00000013  C9                leave
  # 00000014  C3                ret

  def ruby_nil
    nil
  end

  def ruby
    $n.times do; end
  end
end

counter = Counter.new

raise "bad c_nil"   unless counter.cee_nil.nil?
raise "bad asm_nil" unless counter.asm_nil.nil?
raise "bad c"       unless counter.cee  == $n
raise "bad asm2"    unless counter.asm2 == $n
raise "bad asm"     unless counter.asm  == $n
raise "bad ruby"    unless counter.ruby == $n

puts "# of iterations = #{max}"
puts "$n = #{$n}"
puts
Benchmark::bm(20) do |x|
  x.report("null_time") do
    for i in 0..max do
      # do nothing
    end
  end

  %w(cee_nil asm_nil ruby_nil cee asm2 asm ruby).each do |name|
    eval "
      x.report(#{name.inspect}) do
        for i in 0..max do
          counter.#{name}
        end
      end
    "
  end
end
