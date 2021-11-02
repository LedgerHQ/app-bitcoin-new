/*******************************************************************************
*   Ledger Blue - Secure firmware
*   (c) 2016, 2017, 2018, 2019, 2020 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

/**
 * Global chip memory layout and constants
 *
 */
MEMORY
{
  DISCARD (rwx) : ORIGIN = 0xd0000000, LENGTH = 1M

  FLASH   (rx)  : ORIGIN = 0xc0d00000, LENGTH = 400K
  SRAM    (rwx) : ORIGIN = 0x20000200, LENGTH = 4K+512
  CXSRAM  (rwx) : ORIGIN = 0x20001400, LENGTH = 1K
}

PAGE_SIZE  = 64;
STACK_SIZE = DEFINED(stack_size) ? stack_size : 1024;
END_STACK  = ORIGIN(SRAM) + LENGTH(SRAM);

/*
 * Ensure correct remap cx address
 */
OFF_G_cx           = 0x20001400 - ORIGIN(CXSRAM);
_cx_trampoline     = 0x120001;

/*
 * Declare application entry point
 */
ENTRY(main);


/*
 * Layout
 */
SECTIONS
{
  /****************************************************************/
  /* This section locates the code in FLASH                       */
  /****************************************************************/

  /** put text in Flash memory, VMA will be equal to LMA */
  .text :
  {
    /* provide start code symbol, shall be zero */
    _text = .;
    _nvram_start = .;

    /* ensure main is always @ 0xC0D00000 */
    *(.boot*)

    /* place the other code and rodata defined BUT nvram variables that are displaced in a r/w area */
    *(.text*)
    *(.rodata)
    *(.rodata.[^N]*) /*.data.rel.ro* not here to detect invalid PIC usage */
    *(.rodata.N[^_]*)

    . = ALIGN(4);

    /* all code placed */
    _etext = .;

    . = ALIGN(PAGE_SIZE);

    _nvram_data = .;

    /* NVM data (ex-filesystem) */
    *(.bss.N_* .rodata.N_*)

    . = ALIGN(PAGE_SIZE);
    _envram_data = .;

    _install_parameters = .;
    _nvram_end = .;
  } > FLASH = 0x00

  .data (NOLOAD):
  {
    . = ALIGN(4);

    /**
     * Place RAM initialized variables
     */
    _data = .;

    *(vtable)
    *(.data*)

    _edata = .;

  } > DISCARD /*> SRAM AT>FLASH = 0x00 */


  /*
   * Here is the 1K for global var of libcxng
   */
  .cx_ram : {
    _cxram = .;

    . = _cxram + OFF_G_cx;
    *(.bss.G_cx)

    . = _cxram + LENGTH(CXSRAM);
  } > CXSRAM = 0x00

  /*
   * Overlapping sections for the legacy/new globals in the .bss section
   */
  .ol0 (NOLOAD) : 
  {
    bss_start = .; 
    *(.legacy_globals)
    *(.bss.vars) /* legacy global variable not following the G_ convention for globals */
  }  > SRAM = 0x00
  .ol1 bss_start (NOLOAD) : {
    *(.new_globals)
    . = MAX (., bss_start + SIZEOF (.ol0));
  }  > SRAM = 0x00

  .bss bss_start :
  {
    /**
     * Skip space used by the overlays
     */
    . = bss_start + MAX (SIZEOF (.ol0), SIZEOF (.ol1));

    /**
     * Place RAM uninitialized variables
     */
    _bss = .;
    *(.bss*)
    _ebss = .;

    /**
     * Reserve stack size
     */
    . = ALIGN(4);
    app_stack_canary = .;
    PROVIDE(app_stack_canary = .);
    . += 4;
    _stack_validation = .;
    . = _stack_validation + STACK_SIZE;
    _stack = ABSOLUTE(END_STACK) - STACK_SIZE;
    PROVIDE( _stack = ABSOLUTE(END_STACK) - STACK_SIZE);
    _estack = ABSOLUTE(END_STACK);
    PROVIDE( _estack = ABSOLUTE(END_STACK) );

  } > SRAM = 0x00



  /****************************************************************/
  /* DEBUG                                                        */
  /****************************************************************/

  /* remove the debugging information from the standard libraries */
  DEBUG (NOLOAD) :
  {
    libc.a ( * )
    libm.a ( * )
    libgcc.a ( * )
    *(.ARM.exidx* .gnu.linkonce.armexidx.*)
  }

  /DISCARD/ :
  {
    *(.ARM.extab)
    *(.gnu.hash)
    *(.hash)
    *(.dynsym)
    *(.dynstr)
  }

  /* Stabs debugging sections.  */
  .stab          0 : { *(.stab) }
  .stabstr       0 : { *(.stabstr) }
  .stab.excl     0 : { *(.stab.excl) }
  .stab.exclstr  0 : { *(.stab.exclstr) }
  .stab.index    0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }
  .comment       0 : { *(.comment) }

  /* DWARF debug sections.
      Symbols in the DWARF debugging sections are relative to the beginning
      of the section so we begin them at 0.  */
  /* DWARF 1 */
  .debug          0 : { *(.debug) }
  .line           0 : { *(.line) }
  /* GNU DWARF 1 extensions */
  .debug_srcinfo  0 : { *(.debug_srcinfo) }
  .debug_sfnames  0 : { *(.debug_sfnames) }
  /* DWARF 1.1 and DWARF 2 */
  .debug_aranges  0 : { *(.debug_aranges) }
  .debug_pubnames 0 : { *(.debug_pubnames) }
  /* DWARF 2 */
  .debug_info     0 : { *(.debug_info .gnu.linkonce.wi.*) }
  .debug_abbrev   0 : { *(.debug_abbrev) }
  .debug_line     0 : { *(.debug_line) }
  .debug_frame    0 : { *(.debug_frame) }
  .debug_str      0 : { *(.debug_str) }
  .debug_loc      0 : { *(.debug_loc) }
  .debug_macinfo  0 : { *(.debug_macinfo) }
  /* SGI/MIPS DWARF 2 extensions */
  .debug_weaknames 0 : { *(.debug_weaknames) }
  .debug_funcnames 0 : { *(.debug_funcnames) }
  .debug_typenames 0 : { *(.debug_typenames) }
  .debug_varnames  0 : { *(.debug_varnames) }
}

PROVIDE(_nvram = ABSOLUTE(_nvram_start));
PROVIDE(_envram = ABSOLUTE(_nvram_end));
