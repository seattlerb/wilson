
require 'test/unit'
require 'wilson'

class X
  def counter
    n = 1000

    asm :count_to_n do
      eax.mov 0
      count = self.label
      eax.inc
      eax.cmp n
      jne count

      to_ruby eax
    end
  end
end

class TestWilson < Test::Unit::TestCase
  # MachineCodeX86Test initialize-release

  def setup
    @asm = Wilson::MachineCodeX86.new
    @stream = asm.stream
  end

  attr_reader :asm, :stream

  defasm :passthrough, :n do
    eax.mov arg(0) # add n as-is
  end

  defasm :add_to_n, :n do
    eax.mov arg(0) # set eax to n
    eax.add 2      # increment ruby fixnum directly
  end

  def test_wtf_inline!
    assert_equal 1000, X.new.counter
  end

  def test_wtf1?
    assert_equal 42, add_to_n(41)
  end

  def test_wtf2?
    assert_equal 42, passthrough(42)
  end

  # MachineCodeX86Test testing ow/od

  def test_mov_offset_eax
    256.m.mov asm.eax
    assert_equal [0xA3, 0, 1, 0, 0], stream
  end

  def test_mov_eax_offset
    asm.eax.mov 256.m
    assert_equal [0xA1, 0, 1, 0, 0], stream
  end

  # MachineCodeX86Test testing reg<32, mem

  def test_mov_al_big_offset
    asm.al.mov 256.m
    assert_equal [0xA0, 0, 1, 0, 0], stream
  end

  def test_mov_cl_m_edx
    asm.cl.mov asm.edx.m
    assert_equal [0x8A, 0b00001010], stream
  end

  def test_mov_ax_m_ecx
    asm.ax.mov asm.ecx.m
    assert_equal [0x66, 0x8B, 1], stream
  end

  def test_mov_cl_offset
    asm.cl.mov 1.m
    assert_equal [0x8A, 0x0D, 1, 0, 0, 0], stream
  end

  def test_mov_ax_big_offset
    asm.ax.mov 256.m
    assert_equal [0x66, 0xA1, 0, 1, 0, 0], stream
  end

  def test_mov_al_offset
    asm.al.mov 1.m
    assert_equal [0xA0, 1, 0, 0, 0], stream
  end

  def test_mov_cx_offset
    asm.cx.mov 1.m
    assert_equal [0x66, 0x8B, 0x0D, 1, 0, 0, 0], stream
  end

  def test_mov_cx_m_edx
    asm.cx.mov asm.edx.m
    assert_equal [0x66, 0x8B, 0b00001010], stream
  end

  def test_mov_ax_offset
    asm.ax.mov 1.m
    assert_equal [0x66, 0xA1, 1, 0, 0, 0], stream
  end

  def test_mov_al_m_ecx
    asm.al.mov asm.ecx.m
    assert_equal [0x8A, 1], stream
  end

  # MachineCodeX86Test testing /r reg/reg

  def test_mov_eax_ebx
    asm.eax.mov asm.ebx
    assert_equal [0x89, 0b11011000], stream
  end

  def test_mov_ebx_ecx
    asm.ebx.mov asm.ecx
    assert_equal [0x89, 0b11001011], stream
  end

  # MachineCodeX86Test testing /n reg

  def test_bt_ecx_literal
    asm.ecx.bt 1
    assert_equal [0x0F, 0xBA, 0b11100001, 1], stream
  end

  def test_fdivr
    asm.ecx.m.fdivr
    assert_equal [0xD8, 0b00000001], stream
  end

  # MachineCodeX86Test testing []

  def test_bracket_argument
    asm.eax.mov { asm.ecx }
    assert_equal [0x8B, 1], stream
  end

#   def test_bracket_receiver # HACK
#     asm.assemble { [asm.ecx].mov asm.eax }
#     assert_equal [0x89, 1], stream
#   end

  # MachineCodeX86Test testing ib/iw/id

  def test_add_eax_literal
    asm.eax.add 256
    assert_equal [5, 0, 1, 0, 0], stream
  end

  def test_add_ax_literal
    asm.ax.add 256
    assert_equal [0x66, 5, 0, 1], stream
  end

  def test_add_al_literal
    asm.al.add 1
    assert_equal [4, 1], stream
  end

  # MachineCodeX86Test testing rb/rw/rd

  def test_label_jmp_veryFar
    label = asm.label
    65536.times { asm.stream << 0x90 } # cheaters way to do nop, so it runs faster
    label.jmp
    assert_equal 65536 + 5, stream.size
    assert_equal [0xE9, 0xFB, 0xFF, 0xFE, 0xFF], stream[65536..-1]
  end

  def test_jmp_big_offset
    asm.jmp 256.m
    assert_equal [0xFF, 0b00100101, 0, 1, 0, 0], stream
  end

  def test_jmp_m_ecx
    asm.jmp asm.ecx.m
    assert_equal [0xFF, 0b00100001], stream
  end

  def test_jmp_infinite
    label = asm.label
    label.jmp
    assert_equal [0xEB, 0xFE], stream
  end

  def test_label_jmp_far
    asm.bits = 16
    label = asm.label
    256.times { stream << 0x90 } # cheaters way to do nop, so it runs faster
    label.jmp
    assert_equal 256 + 3, stream.size
    assert_equal [0xE9, 0xFD, 0xFE], stream[256..-1]
  end

  def test_jmp_forward_and_backward
    label = asm.future_label
    label.jmp
    asm.nop
    label.plant
    label.jmp
    assert_equal [0xE9, 1, 0, 0, 0, 0x90, 0xEB, 0xFE], stream
  end

  def test_jmp_forward
    label = asm.future_label
    label.jmp
    asm.nop
    label.plant
    assert_equal [0xE9, 1, 0, 0, 0, 0x90], stream
  end

  def test_jmp_offset
    asm.jmp 1.m
    assert_equal [0xFF, 0b00100101, 1, 0, 0, 0], stream
  end

  def test_jmp_far
    asm.jmp 256
    assert_equal [0xE9, 0xFB, 0, 0, 0], stream
  end

  def test_loop_infinite
    label = asm.label
    label.loop
    assert_equal [0xE2, 0xFE], stream
  end

  # MachineCodeX86Test testing o16/o32

  def test_adc_ax_literal
    asm.bits = 32
    asm.ax.add 1
    assert_equal [0x66, 5, 1, 0], stream
  end

  def test_adc_ax_literal16
    asm.bits = 32
    asm.ax.add 256
    assert_equal [0x66, 5, 0, 1], stream
  end

  def test_adc_eax_literal
    asm.bits = 16
    asm.eax.add 1
    assert_equal [0x67, 0x83, 0b11000000, 1], stream
  end

  def test_adc_eax_literal16
    asm.bits = 16
    asm.eax.add 256
    assert_equal [0x67, 5, 0, 1, 0, 0], stream
  end

  # MachineCodeX86Test testing cpuregs

  def test_mov_ecx_cr0
    asm.ecx.mov asm.cr0
    assert_equal [0x0f, 0x20, 0b11000001], stream
  end

  def test_mov_dr0Ecx
    asm.dr0.mov asm.ecx
    assert_equal [0x0f, 0x23, 0b11000001], stream
  end

  def test_mov_ecx_tr3
    asm.ecx.mov asm.tr3
    assert_equal [0x0f, 0x24, 0b11011001], stream
  end

  def test_mov_tr3_ecx
    asm.tr3.mov asm.ecx
    assert_equal [0x0f, 0x26, 0b11011001], stream
  end

  def test_mov_ecx_dr0
    asm.ecx.mov asm.dr0
    assert_equal [0x0f, 0x21, 0b11000001], stream
  end

  def test_mov_cr0_ecx
    asm.cr0.mov asm.ecx
    assert_equal [0x0f, 0x22, 0b11000001], stream
  end

  # MachineCodeX86Test testing /r reg/mem

  def test_mov_eax_m_ecx
    asm.eax.mov asm.ecx.m
    assert_equal [0x8B, 0b00000001], stream
  end

  def test_mov_ebx_m_ecx_edx_offset
    asm.ebx.mov(asm.ecx + asm.edx + 1)
    assert_equal [0x8B, 0b00011100, 0b01010001, 1], stream
  end

  def test_mov_ebx_m_ecx_edx
    asm.ebx.mov(asm.ecx + asm.edx)
    assert_equal [0x8B, 0b00011100, 0b00010001], stream
  end

  def test_mov_ebx_m_ecx_edx_big_offset
    asm.ebx.mov(asm.ecx + asm.edx + 256)
    assert_equal [0x8B, 0b00011100, 0b10010001, 0, 1, 0, 0], stream
  end

  def test_mov_eax_m_ecx_big_offset
    asm.eax.mov asm.ecx + 256
    assert_equal [0x8B, 0b10000001, 0, 1, 0, 0], stream
  end

  def test_mov_ecx_m_offset
    asm.ecx.mov 256.m
    assert_equal [0x8B, 0x0D, 0, 1, 0, 0], stream
  end

  def test_mov_eax_m_ecx_offset
    asm.eax.mov asm.ecx + 1
    assert_equal [0x8B, 0b01000001, 1], stream
  end

  # MachineCodeX86Test testing imm:imm

  def test_jmp_imm_Imm32
    asm.jmp 256, 65537
    assert_equal [0xEA, 1, 0, 1, 0, 0, 1], stream
  end

  def test_call_imm_Imm16
    asm.call 1, 2
    assert_equal [0x66, 0x9A, 2, 0, 1, 0], stream
  end

  def test_jmp_imm_Imm16
    asm.jmp 1, 2
    assert_equal [0x66, 0xEA, 2, 0, 1, 0], stream
  end

  def test_call_imm_Imm32
    asm.call 256, 65537
    assert_equal [0x9A, 1, 0, 1, 0, 0, 1], stream
  end

  # MachineCodeX86Test testing 0 args

  def test_ret
    asm.ret
    assert_equal [0xC3], stream
  end

  def test_nop
    asm.nop
    assert_equal [0x90], stream
  end

  def test_hlt
    asm.hlt
    assert_equal [0xF4], stream
  end

  # MachineCodeX86Test testing 3 args

  def test_imul_ecx_edx_immediate
    asm.ecx.imul asm.edx, 1
    assert_equal [0x6B, 0xCA, 1], stream
  end

  def test_imul_ecx_edx_big_immediate
    asm.ecx.imul asm.edx, 256
    assert_equal [0x69, 0xCA, 0, 1, 0, 0], stream
  end

  # MachineCodeX86Test testing fpureg

  def test_fadd_st0St1
    asm.st0.fadd asm.st1
    assert_equal [0xD8, 0xC1], stream
  end

  def test_fmulp_st1St0
    asm.st1.fmulp asm.st0
    assert_equal [0xDE, 0xC9], stream
  end

  def test_fadd_st0
    asm.st0.fadd
    assert_equal [0xD8, 0xC0], stream
  end

  def test_fadd_st1
    asm.st1.fadd
    assert_equal [0xD8, 0xC1], stream
  end

  # MachineCodeX86Test testing /n mem

  def test_fild_m_ecx_edx_offset
    (asm.ecx + asm.edx + 1).fild
    assert_equal [0xDB, 0b00000100, 0b01010001, 1], stream
  end

  def test_bt_m_ecx_literal
    # ... this shouldn't work. The machine code generated here does
    # not work and nasm complains that a size was not specified if you
    # try to write the same code in nasm -> mov [ecx], 1
    #
    # Some how we're meant to know this is invalid and throw an
    # error.. not sure how yet.
    asm.ecx.m.bt 1
    assert_equal [0x0F, 0xBA, 0b00100001, 1], stream
  end

  def test_fild_m_ecx_big_offset
    (asm.ecx + 256).fild
    assert_equal [0xDB, 0b10000001, 0, 1, 0, 0], stream
  end

  def test_fild_m_ecx_edx
    (asm.ecx + asm.edx).fild
    assert_equal [0xDB, 0b00000100, 0b00010001], stream
  end

  def test_fild_m_ecx_edx_big_offset
    (asm.ecx + asm.edx + 256).fild
    assert_equal [0xDB, 0b00000100, 0b10010001, 0, 1, 0, 0], stream
  end

  def test_fild_m_ecx
    asm.ecx.m.fild
    assert_equal [0xDB, 0b00000001], stream
  end

  def test_fild_m_ecx_offset
    (asm.ecx + 1).fild
    assert_equal [0xDB, 0b01000001, 1], stream
  end

  # MachineCodeX86Test testing processors

#   def testing_adc_edx_ecx # HACK
#     asm.processors.reject! { |processor| processor == '386' }
#     assert_raise NoMethodError do
#       asm.edx.adc asm.ecx
#     end
#   end

  # MachineCodeX86Test testing mmxreg

  def test_psllw_mm1Immediate
    asm.mm1.psllw 1
    assert_equal [0x0F, 0x71, 0xF1, 1], stream
  end

  def test_movd_eax_mm0
    asm.eax.movd asm.mm0
    assert_equal [0x0F, 0x7E, 0xC0], stream
  end

  def test_movd_mm0Eax
    asm.mm0.movd asm.eax
    assert_equal [0x0F, 0x6E, 0xC0], stream
  end

  # MachineCodeX86Test testing +r

  def test_mov_ecx_literal
    asm.ecx.mov 1
    assert_equal [0xB9, 1, 0, 0, 0], stream
  end

  def test_mov_edx_literal
    asm.edx.mov 1
    assert_equal [0xBA, 1, 0, 0, 0], stream
  end

  def test_mov_eax_literal
    asm.eax.mov 1
    assert_equal [0xB8, 1, 0, 0, 0], stream
  end

  def test_mov_ebx_literal
    asm.ebx.mov 1
    assert_equal [0xBB, 1, 0, 0, 0], stream
  end

  # MachineCodeX86Test testing /r mem/reg

  def test_mov_m_ecx_edx_offset_ebx
    (asm.ecx + asm.edx + 1).mov asm.ebx
    assert_equal [0x89, 0b00011100, 0b01010001, 1], stream
  end

  def test_mov_m_eax_ecx
    asm.eax.m.mov asm.ecx
    assert_equal [0x89, 0b00001000], stream
  end

  def test_mov_m_ecx_big_offset_ebx
    (asm.ecx + 256).mov asm.ebx
    assert_equal [0x89, 0b10011001, 0, 1, 0, 0], stream
  end

  def test_mov_m_ecx_edx_big_offset_ebx
    (asm.ecx + asm.edx + 256).mov asm.ebx
    assert_equal [0x89, 0b00011100, 0b10010001, 0, 1, 0, 0], stream
  end

  def test_mov_m_ecx_offset_ebx
    (asm.ecx + 1).mov asm.ebx
    assert_equal [0x89, 0b01011001, 1], stream
  end

  def test_mov_m_ecx_eax
    asm.ecx.m.mov asm.eax
    assert_equal [0x89, 0b00000001], stream
  end

  def test_mov_m_ecx_edx_ebx
    (asm.ecx + asm.edx).mov asm.ebx
    assert_equal [0x89, 0b00011100, 0b00010001], stream
  end

  # MachineCodeX86Test testing +cc

  def test_cmovne_eax_ecx
    asm.eax.cmovne asm.ecx
    assert_equal [0x0F, 0x45, 0xC1], stream
  end

  def test_cmove_eax_ecx
    asm.eax.cmove asm.ecx
    assert_equal [0x0F, 0x44, 0xC1], stream
  end

  def test_jnb
    asm.label.jnb
    assert_equal [0x73, 0xFE], stream
  end

  def test_jnc
    asm.label.jnc
    assert_equal [0x73, 0xFE], stream
  end

  def test_jno
    asm.label.jno
    assert_equal [0x71, 0xFE], stream
  end

  def test_jae
    asm.label.jae
    assert_equal [0x73, 0xFE], stream
  end

  def test_jnae
    asm.label.jnae
    assert_equal [0x72, 0xFE], stream
  end

  def test_cmovz_eax_ecx
    asm.eax.cmovz asm.ecx
    assert_equal [0x0F, 0x44, 0xC1], stream
  end

  def test_jb
    asm.label.jb
    assert_equal [0x72, 0xFE], stream
  end

  def test_jc
    asm.label.jc
    assert_equal [0x72, 0xFE], stream
  end

  def test_cmovnz_eax_ecx
    asm.eax.cmovnz asm.ecx
    assert_equal [0x0F, 0x45, 0xC1], stream
  end

  def test_jo
    asm.label.jo
    assert_equal [0x70, 0xFE], stream
  end

  # MachineCodeX86Test testing reg,1/cl

  def test_rcr_eax1
    asm.eax.rcr 1
    assert_equal [0xD1, 0xD8], stream
  end

  def test_rcr_eaxCl
    asm.eax.rcr asm.cl
    assert_equal [0xD3, 0xD8], stream
  end

  # MachineCodeX86Test testing segreg

  def test_mov_fs_m_eax
    asm.fs.mov asm.eax.m
    assert_equal [0x8E, 0x20], stream
  end

  def test_mov_eaxFs
    asm.eax.mov asm.fs
    assert_equal [0x8C, 0xE0], stream
  end

  def test_mov_m_eaxFs
    asm.eax.m.mov asm.fs
    assert_equal [0x8C, 0x20], stream
  end

  def test_mov_fs_eax
    asm.fs.mov asm.eax
    assert_equal [0x8E, 0xE0], stream
  end
end
