= wilson

* http://rubyforge.org/projects/seattlerb

== DESCRIPTION:

Wilson is a pure ruby x86 assembler. No, really. Worst Idea Evar.

Why "wilson"? I wanted to name it "metal", but there is an existing
project with that name... So I'm naming it after Wilson Bilkovich, who
is about as metal as you can get (and it is easier to spell than
"bilkovich", even tho that sounds more metal).

== FEATURES/PROBLEMS:

* Generates x86 machine code directly. No dependencies. No system calls.
* Registers ruby methods with #defasm, or run inline assembly with #asm.
* Terrible, yet, awesome.

== SYNOPSIS:

  class X
    defasm :superfast_meaning_of_life do
      eax.mov 42
      to_ruby eax # ruby fixnums = (n << 1) + 1
    end

    def inline_asm_example
      n = 1000
  
      asm :count_to_n do
        eax.xor eax
        count = self.label
        eax.inc
        eax.cmp n
        jne count
  
        to_ruby eax
      end
    end
  end
  
  p X.new.superfast_meaning_of_life # => 42
  p X.new.inline_asm_example        # => 1000

== REQUIREMENTS:

* rubygems

== INSTALL:

* sudo gem install wilson

== LICENSE:

(The MIT License)

Copyright (c) 2008-2009 Ryan Davis, Seattle.rb

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
