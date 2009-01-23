#!/usr/bin/ruby -w

require 'test/unit'
$: << 'lib'
require 'wilson'

class Wilson::MachineCodeX86
  def to_ruby reg
    self.ebx.mov reg
    self.imul reg, 2
    reg.inc
  end
end

class Examples
  defasm :count_to_ten do
    # eax.mov 0
    # ecx.mov 10
    # count = self.label
    # eax.add 1
    # count.loop
  end

  defasm :three_plus_four do
    eax.mov 3
    eax.add 4
    # to_ruby eax
  end

  defasm :jump_forward do
    # future = self.future_label
    # eax.xor eax
    # future.jmp
    # eax.inc
    # future.plant
  end

  defasm :first_in_array, :array do
    # edx.mov array
    # eax.xor eax
    # al.mov edx
  end

  defasm :add, :a, :b do
    # eax.mov a
    # eax.add b
  end

  defasm :sum, :array, :len do
    # edx.mov array
    # ecx.mov len
    # ecx.dec
    # eax.xor eax
    # al.add edx

    # repeat = self.label
    #   al.add edx + ecx
    # repeat.loop
  end
end

class TestExamples < Test::Unit::TestCase
  def setup
    @x = Examples.new
  end

  def test_three_plus_four
    assert_equal 7, @x.three_plus_four
  end

  def test_three_plus_four_again
    assert_equal 7, @x.three_plus_four
  end

  def test_jump_forward
    # assert_equal false, @x.jump_forward
  end

  def test_count_to_ten
    # assert_equal 10, @x.count_to_ten
  end

  def test_add
    # assert_equal 7, @x.add(3, 4)
  end

  def test_first_in_array
    # array = [5, 6, 7, 8, 9, 100]
    # assert_equal 5, @x.first_in_array(array)
  end

  def test_sum
    #     | array |
    #     array = #[ 5 6 7 8 9 100 ] gc_copy_to_heap
    #     self assert: (Sum call_with: array with: 5) = 35
  end
end

class ARC4
  # ARC4 API

  # encryptInPlace: byteArray length: length
  #     | array |
  #     array = byteArray gcCopyToHeap
  #     self encryptArrayOnHeap: array length: length
  #     array copyAt: 0 to: byteArray size: length startingAt: 1

  # encrypt: string
  #     | array result |
  #     array = string gcCopyToHeap
  #     self encryptArrayOnHeap: array length: string size
  #     result = ByteArray new: string size
  #     array copyAt: 0 to: result size: string size startingAt: 1
  #     ^result

  # setKey: key
  #     self s: (Security.ARC4 new setKey: key asByteArray) s i: 0 j: 0

  # encryptArrayOnHeap: array length: length
  #     | args |
  #     args = Array new: 5
  #     args at: 1 put: array
  #     args at: 2 put: length
  #     args at: 3 put: s
  #     args at: 4 put: i
  #     args at: 5 put: j
  #     ARC4Encrypt type baseType call: ARC4Encrypt withArguments: args

  # ARC4 assembler

  # repeat: times do: aBlock
  #     | repeat |
  #     ecx mov: times
  #     repeat = self label
  #         ecx push
  #         aBlock value
  #         ecx pop
  #     repeat loop

  # arc4_encrypt: pArray len: len s: pS i: pI j: pJ
  #     <asm: void ARC4Encrypt( unsigned char* array, unsigned int len, unsigned char* s, unsigned int* i, unsigned int* j)>
  # "   edi = current character of @array that we're encrypting
  #     esi = address of @s keystream
  #     ecx = @len counting down
  #     eax = current math
  #     ebx = @i
  #     edx = @j
  #     current character to be encoded = [edi]
  #     current character at s[i] = [esi+ebx]
  #     current character at s[j] = [esi+edx]
  # "
  #     ebx get: pI
  #     edx get: pJ
  #     esi mov: pS
  #     edi mov: pArray
  #     self repeat: len do: [
  #         bl inc. "i = (i + 1) mod: 255"
  #         al mov: [esi+ebx]. "si = s[i]"
  #         dl add: [esi+ebx]. "j = (j + s[i]) mod 256"
  #         cl mov: [esi+edx]. "sj = s[j]"
  #         "swap S[i] and S[j]"
  #         [esi+edx] mov: al. "s[j] = si"
  #         [esi+ebx] mov: cl. "s[i] = sj"
  #         al add: cl. "s[i] + s[j]"
  #         al mov: [esi+eax]. "s[s] mod 256"
  #         "array ^ s[s]"
  #         al xor: [edi]
  #         [edi] mov: al
  #         edi add: 1
  #     ]
  #     eax mov: pI
  #     [eax] mov: ebx
  #     eax mov: pJ
  #     [eax] mov: edx

  # ARC4 initialize-release

  # s: anS i: aI j: aJ
  #     s = anS gcCopyToHeap
  #     i = aI gcCopyToHeap
  #     j = aJ gcCopyToHeap
end

class TestARC4 < Test::Unit::TestCase
  # ARC4Test testing

  def testAttackAtDawn
    #     | encrypted |
    #     encrypted = ARC4 new setKey: 'Secret'; encrypt: 'Attack at dawn'
    #     self assert: (self decrypt: encrypted key: 'Secret') = 'Attack at dawn'

    # decrypt: array key: key
    #     | arc4 |
    #     (arc4 = Security.ARC4 new) setKey: key asByteArray
    #     ^(array collect: [:e | arc4 decryptByte: e]) asString
  end

  def testPlaintext
    #     | encrypted |
    #     encrypted = ARC4 new setKey: 'Key'; encrypt: 'Plaintext'
    #     self assert: (self decrypt: encrypted key: 'Key') = 'Plaintext'
  end

  def testWikipedia
    #     | encrypted |
    #     encrypted = ARC4 new setKey: 'Wiki'; encrypt: 'pedia'
    #     self assert: (self decrypt: encrypted key: 'Wiki') = 'pedia'
  end
end
