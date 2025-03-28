unit binarybase;

{$mode FPC}

interface

type Integer=-$7FFFFFFF..$7FFFFFFF;

const elf_file_identify:array[1..4] of byte=($7F,Byte('E'),Byte('L'),Byte('F'));
      elf_class_pos=5;
      elf_data_pos=6;
      elf_version_pos=7;
      elf_osabi_pos=8;
      elf_abiversion_pos=8;
      elf_pad_pos=9;
      elf_identify_size=16;
      elf_class_none=0;
      elf_class_32=1;
      elf_class_64=2;
      elf_data_none=0;
      elf_data_least_byte=1;
      elf_data_most_byte=2;
      elf_osabi_none=0;
      elf_osabi_hpux=1;
      elf_osabi_netbsd=2;
      elf_osabi_gnu=3;
      elf_osabi_linux=3;
      elf_osabi_solaris=6;
      elf_osabi_aix=7;
      elf_osabi_irix=8;
      elf_osabi_freebsd=9;
      elf_osabi_tru64=10;
      elf_osabi_modesto=11;
      elf_osabi_openbsd=12;
      elf_osabi_openvms=13;
      elf_osabi_nsk=14;
      elf_osabi_aros=15;
      elf_osabi_fenixos=16;
      elf_osabi_cloudapi=17;
      elf_osabi_openvos=18;
      elf_osabi_tydqos=19;
      elf_type_none=0;
      elf_type_relocation=1;
      elf_type_executable=2;
      elf_type_dynamic=3;
      elf_type_core=4;
      elf_type_os_low=$FE00;
      elf_type_os_high=$FEFF;
      elf_type_processor_low=$FF00;
      elf_type_processor_high=$FFFF;
      elf_machine_none=0;
      elf_machine_m32=1;
      elf_machine_sparc=2;
      elf_machine_386=3;
      elf_machine_68k=4;
      elf_machine_88k=5;
      elf_machine_iamcu=6;
      elf_machine_860=7;
      elf_machine_mips=8;
      elf_machine_s370=9;
      elf_machine_mips_rs3_le=10;
      elf_machine_parisc=15;
      elf_machine_vpp500=17;
      elf_machine_sparc32plus=18;
      elf_machine_960=19;
      elf_machine_ppc=20;
      elf_machine_ppc64=21;
      elf_machine_s390=22;
      elf_machine_spu=23;
      elf_machine_v800=36;
      elf_machine_fr20=37;
      elf_machine_rh32=38;
      elf_machine_rce=39;
      elf_machine_arm=40;
      elf_machine_alpha=41;
      elf_machine_sh=42;
      elf_machine_sparcv9=43;
      elf_machine_tricore=44;
      elf_machine_arc=45;
      elf_machine_h8_300=46;
      elf_machine_h8_300h=47;
      elf_machine_h8s=48;
      elf_machine_h8_500=49;
      elf_machine_ia_64=50;
      elf_machine_mips_x=51;
      elf_machine_coldfire=52;
      elf_machine_68hc12=53;
      elf_machine_mma=54;
      elf_machine_pcp=55;
      elf_machine_ncpu=56;
      elf_machine_ndr1=57;
      elf_machine_starcore=58;
      elf_machine_me16=59;
      elf_machine_st100=60;
      elf_machine_tinyj=61;
      elf_machine_x86_64=62;
      elf_machine_pdsp=63;
      elf_machine_pdp10=64;
      elf_machine_pdp11=65;
      elf_machine_fx66=66;
      elf_machine_st9plus=67;
      elf_machine_st7=68;
      elf_machine_68hc16=69;
      elf_machine_68hc11=70;
      elf_machine_68hc08=71;
      elf_machine_68hc05=72;
      elf_machine_svx=73;
      elf_machine_st19=74;
      elf_machine_vax=75;
      elf_machine_cris=76;
      elf_machine_javelin=77;
      elf_machine_firepath=78;
      elf_machine_zsp=79;
      elf_machine_mmix=80;
      elf_machine_huany=81;
      elf_machine_prism=82;
      elf_machine_avr=83;
      elf_machine_fr30=84;
      elf_machine_d10v=85;
      elf_machine_d30v=86;
      elf_machine_v850=87;
      elf_machine_m32r=88;
      elf_machine_mn10300=89;
      elf_machine_mn10200=90;
      elf_machine_pj=91;
      elf_machine_openrisc=92;
      elf_machine_arc_compact=93;
      elf_machine_xtensa=94;
      elf_machine_videocore=95;
      elf_machine_tmm_gpp=96;
      elf_machine_ns32k=97;
      elf_machine_tpc=98;
      elf_machine_snp1k=99;
      elf_machine_st200=100;
      elf_machine_ip2k=101;
      elf_machine_max=102;
      elf_machine_cr=103;
      elf_machine_f2mc16=104;
      elf_machine_msp430=105;
      elf_machine_blackpin=106;
      elf_machine_se_c33=107;
      elf_machine_sep=108;
      elf_machine_arca=109;
      elf_machine_unicore=110;
      elf_machine_excess=111;
      elf_machine_dxp=112;
      elf_machine_altera_nios2=113;
      elf_machine_crx=114;
      elf_machine_xgate=115;
      elf_machine_c166=116;
      elf_machine_m16c=117;
      elf_machine_dspic30f=118;
      elf_machine_ce=119;
      elf_machine_m32c=120;
      elf_machine_tsk3000=131;
      elf_machine_rs08=132;
      elf_machine_sharc=133;
      elf_machine_ecog2=134;
      elf_machine_score7=135;
      elf_machine_dsp24=136;
      elf_machine_videocore3=137;
      elf_machine_latticemico32=138;
      elf_machine_se_c17=139;
      elf_machine_ti_c6000=140;
      elf_machine_ti_c2000=141;
      elf_machine_ti_c5500=142;
      elf_machine_ti_arp32=143;
      elf_machine_ti_pru=144;
      elf_machine_mmdsp_plus=160;
      elf_machine_cypress_m8c=161;
      elf_machine_r32c=162;
      elf_machine_trimedia=163;
      elf_machine_qdsp6=164;
      elf_machine_8051=165;
      elf_machine_stxp7x=166;
      elf_machine_nds32=167;
      elf_machine_ecog1=168;
      elf_machine_ecog1x=168;
      elf_machine_maxq30=169;
      elf_machine_ximo16=170;
      elf_machine_manik=171;
      elf_machine_craynv2=172;
      elf_machine_rx=173;
      elf_machine_metag=174;
      elf_machine_mcst_elbrus=175;
      elf_machine_ecog16=176;
      elf_machine_cr16=177;
      elf_machine_etpu=178;
      elf_machine_sle9x=179;
      elf_machine_l10m=180;
      elf_machine_k10m=181;
      elf_machine_aarch64=183;
      elf_machine_avr32=185;
      elf_machine_stm8=186;
      elf_machine_tile64=187;
      elf_machine_tilepro=188;
      elf_machine_microblaze=189;
      elf_machine_cuda=190;
      elf_machine_tilegx=191;
      elf_machine_cloudshield=192;
      elf_machine_corea_1st=193;
      elf_machine_corea_2nd=194;
      elf_machine_arc_compact2=195;
      elf_machine_open8=196;
      elf_machine_rl78=197;
      elf_machine_videcore=198;
      elf_machine_78kor=199;
      elf_machine_56800ex=200;
      elf_machine_ba1=201;
      elf_machine_ba2=202;
      elf_machine_xcore=203;
      elf_machine_mchp_pic=204;
      elf_machine_km32=210;
      elf_machine_kmx32=211;
      elf_machine_kmx16=212;
      elf_machine_kmx8=213;
      elf_machine_kvarc=214;
      elf_machine_cdp=215;
      elf_machine_coge=216;
      elf_machine_cool=217;
      elf_machine_norc=218;
      elf_machine_csr_kalimba=219;
      elf_machine_z80=220;
      elf_machine_visium=221;
      elf_machine_ft32=222;
      elf_machine_moxie=223;
      elf_machine_amdgpu=224;
      elf_machine_riscv=243;
      elf_machine_loongarch=258;
      elf_version_none=0;
      elf_version_current=1;
      elf_table_header_undefine=0;
      elf_table_header_low_reserve=$FF00;
      elf_table_header_low_processor=$FF00;
      elf_table_header_high_processor=$FF1F;
      elf_table_header_low_os=$FF20;
      elf_table_header_high_os=$FF3F;
      elf_section_header_abs=$FFF1;
      elf_section_header_common=$FFF2;
      elf_section_header_xindex=$FFFF;
      elf_section_header_high_reserve=$FFFF;
      elf_section_header_null=0;
      elf_section_header_progbits=1;
      elf_section_header_symtab=2;
      elf_section_header_strtab=3;
      elf_section_header_rela=4;
      elf_section_header_hash=5;
      elf_section_header_dynamic=6;
      elf_section_header_note=7;
      elf_section_header_nobits=8;
      elf_section_header_rel=9;
      elf_section_header_shlib=10;
      elf_section_header_dynsym=11;
      elf_section_header_init_array=14;
      elf_section_header_fini_array=15;
      elf_section_header_preinit_array=16;
      elf_section_header_group=17;
      elf_section_header_symtab_shndx=18;
      elf_section_header_low_os=$60000000;
      elf_section_header_high_os=$6FFFFFFF;
      elf_section_header_low_processor=$70000000;
      elf_section_header_high_processor=$7FFFFFFF;
      elf_section_header_low_user=$80000000;
      elf_section_header_high_user=$FFFFFFFF;
      elf_section_header_flag_write=1;
      elf_section_header_flag_alloc=2;
      elf_section_header_flag_exec_instr=4;
      elf_section_header_flag_merge=$10;
      elf_section_header_flag_string=$20;
      elf_section_header_flag_info_link=$40;
      elf_section_header_flag_link_order=$80;
      elf_section_header_flag_os_nonconforming=$100;
      elf_section_header_flag_group=$200;
      elf_section_header_flag_tls=$400;
      elf_section_header_flag_compressed=$800;
      elf_section_header_flag_maskos=$0FF00000;
      elf_section_header_flag_maskprocessor=$F0000000;
      elf_compression_header_zlib=1;
      elf_compression_header_low_os=$60000000;
      elf_compression_header_high_os=$6FFFFFFF;
      elf_compression_header_low_processor=$70000000;
      elf_compression_header_high_processor=$7FFFFFFF;
      elf_group_comdat=1;
      elf_group_maskos=$0FF00000;
      elf_group_maskprocessor=$F0000000;
      elf_symbol_binding_local=1;
      elf_symbol_binding_global=2;
      elf_symbol_binding_weak=3;
      elf_symbol_binding_low_os=10;
      elf_symbol_binding_high_os=12;
      elf_symbol_binding_low_processor=13;
      elf_symbol_binding_high_processor=15;
      elf_symbol_type_no_types=0;
      elf_symbol_type_object=1;
      elf_symbol_type_func=2;
      elf_symbol_type_section=3;
      elf_symbol_type_file=4;
      elf_symbol_type_common=5;
      elf_symbol_type_tls=6;
      elf_symbol_type_low_os=10;
      elf_symbol_type_high_os=12;
      elf_symbol_type_low_processor=13;
      elf_symbol_type_high_processor=15;
      elf_symbol_visibility_default=0;
      elf_symbol_visibility_internal=1;
      elf_symbol_visibility_hidden=2;
      elf_symbol_visibility_protected=3;
      elf_program_table_null=0;
      elf_program_table_load=1;
      elf_program_table_dynamic=2;
      elf_program_table_interp=3;
      elf_program_table_note=4;
      elf_program_table_shlib=5;
      elf_program_table_phdr=6;
      elf_program_table_tls=7;
      elf_program_table_low_os=$60000000;
      elf_program_table_high_os=$6FFFFFFF;
      elf_program_table_low_processor=$70000000;
      elf_program_table_high_processor=$7FFFFFFF;
      elf_program_flag_x=1;
      elf_program_flag_w=2;
      elf_program_flag_r=4;
      elf_program_flag_mask_os=$0FF00000;
      elf_program_flag_mask_processor=$F0000000;
      elf_dynamic_tag_null=0;
      elf_dynamic_tag_needed=1;
      elf_dynamic_tag_pltrelsz=2;
      elf_dynamic_tag_pltgot=3;
      elf_dynamic_tag_hash=4;
      elf_dynamic_tag_strtab=5;
      elf_dynamic_tag_symtab=6;
      elf_dynamic_tag_rela=7;
      elf_dynamic_tag_relasz=8;
      elf_dynamic_tag_relaent=9;
      elf_dynamic_tag_strsz=10;
      elf_dynamic_tag_syment=11;
      elf_dynamic_tag_init=12;
      elf_dynamic_tag_fini=13;
      elf_dynamic_tag_soname=14;
      elf_dynamic_tag_rpath=15;
      elf_dynamic_tag_symbolic=16;
      elf_dynamic_tag_rel=17;
      elf_dynamic_tag_relsz=18;
      elf_dynamic_tag_relent=19;
      elf_dynamic_tag_pltrel=20;
      elf_dynamic_tag_debug=21;
      elf_dynamic_tag_textrel=22;
      elf_dynamic_tag_jmprel=23;
      elf_dynamic_tag_bind_now=24;
      elf_dynamic_tag_init_array=25;
      elf_dynamic_tag_fini_array=26;
      elf_dynamic_tag_init_array_size=27;
      elf_dynamic_tag_fini_array_size=28;
      elf_dynamic_tag_runpath=29;
      elf_dynamic_tag_flags=30;
      elf_dynamic_tag_encoding=31;
      elf_dynamic_tag_preinit_array=32;
      elf_dynamic_tag_preinit_array_size=33;
      elf_dynamic_tag_symbol_table_string_table_index=34;
      elf_dynamic_tag_low_os=$6000000D;
      elf_dynamic_tag_high_os=$6FFFF000;
      elf_dynamic_tag_low_processor=$70000000;
      elf_dynamic_tag_high_processor=$7FFFFFFF;
      elf_dynamic_flag_origin=1;
      elf_dynamic_flag_symbolic=2;
      elf_dynamic_flag_textrel=4;
      elf_dynamic_flag_bind_now=8;
      elf_dynamic_flag_static_tls=16;
      pe_image_file_machine_unknown=$0;
      pe_image_file_machine_alpha=$184;
      pe_image_file_machine_alpha64=$284;
      pe_image_file_machine_am33=$1D3;
      pe_image_file_machine_amd64=$8664;
      pe_image_file_machine_arm=$1C0;
      pe_image_file_machine_arm64=$AA64;
      pe_image_file_machine_armnt=$1C4;
      pe_image_file_machine_axp64=$284;
      pe_image_file_machine_ebc=$EBC;
      pe_image_file_machine_i386=$14C;
      pe_image_file_machine_ia64=$200;
      pe_image_file_machine_loongarch32=$6232;
      pe_image_file_machine_loongarch64=$6264;
      pe_image_file_machine_m32r=$9041;
      pe_image_file_machine_mips16=$266;
      pe_image_file_machine_mipsfpu=$366;
      pe_image_file_machine_mipsfpu16=$466;
      pe_image_file_machine_powerpc=$1F0;
      pe_image_file_machine_powerpcfp=$1F1;
      pe_image_file_machine_r4000=$166;
      pe_image_file_machine_riscv32=$5032;
      pe_image_file_machine_riscv64=$5064;
      pe_image_file_machine_riscv128=$5128;
      pe_image_file_machine_sh3=$1A2;
      pe_image_file_machine_sh3dsp=$1A3;
      pe_image_file_machine_sh4=$1A6;
      pe_image_file_machine_sh5=$1A8;
      pe_image_file_machine_thumb=$1C2;
      pe_image_file_machine_wcemipsv2=$169;
      pe_image_file_relocs_stripped=$0001;
      pe_image_file_executable_image=$0002;
      pe_image_file_line_nums_stripped=$0004;
      pe_image_file_local_syms_stripped=$0008;
      pe_image_file_aggressive_ws_trim=$0010;
      pe_image_file_large_address_aware=$0020;
      pe_image_file_bytes_reverse_lo=$0080;
      pe_image_file_32bit_machine=$0100;
      pe_image_file_debug_stripped=$0200;
      pe_image_file_removable_run_from_swap=$0400;
      pe_image_file_net_run_from_swap=$0800;
      pe_image_file_system=$1000;
      pe_image_file_dll=$2000;
      pe_image_file_system_only=$4000;
      pe_image_file_bytes_reversed_hi=$8000;
      pe_image_subsystem_unknown=0;
      pe_image_subsystem_native=1;
      pe_image_subsystem_windows_gui=2;
      pe_image_subsystem_windows_cui=3;
      pe_image_subsystem_os2_cui=5;
      pe_image_subsystem_posix_cui=7;
      pe_image_subsystem_native_windows=8;
      pe_image_subsystem_windows_ce_gui=9;
      pe_image_subsystem_efi_application=10;
      pe_image_subsystem_efi_boot_service_driver=11;
      pe_image_subsystem_efi_runtime_driver=12;
      pe_image_subsystem_efi_rom=13;
      pe_image_subsystem_xbox=14;
      pe_image_subsystem_windows_boot_application=16;
      pe_image_dllcharacteristics_high_entropy_va=$0020;
      pe_image_dllcharacteristics_dynamic_base=$0040;
      pe_image_dllcharacteristics_force_integrity=$0080;
      pe_image_dllcharacteristics_nx_compat=$0100;
      pe_image_dllcharacteristics_no_isolation=$0200;
      pe_image_dllcharacteristics_no_seh=$0400;
      pe_image_dllcharacteristics_no_bind=$0800;
      pe_image_dllcharacteristics_appcontainer=$1000;
      pe_image_dllcharacteristics_wdm_driver=$2000;
      pe_image_dllcharacteristics_guard_cf=$4000;
      pe_image_dllcharacteristics_terminal_server_aware=$8000;
      pe_image_directory_entry_export=0;
      pe_image_directory_entry_import=1;
      pe_image_directory_entry_resource=2;
      pe_image_directory_entry_exception=3;
      pe_image_directory_entry_security=4;
      pe_image_directory_entry_basereloc=5;
      pe_image_directory_entry_debug=6;
      pe_image_directory_entry_architecture=7;
      pe_image_directory_entry_globalptr=8;
      pe_image_directory_entry_tls=9;
      pe_image_directory_entry_load_config=10;
      pe_image_directory_entry_bound_import=11;
      pe_image_directory_entry_iat=12;
      pe_image_directory_entry_delay_import=13;
      pe_image_directory_entry_com_descriptor=14;
      pe_image_pe32_image_magic=$10B;
      pe_image_pe32plus_image_magic=$20B;
      pe_image_perom_image_magic=$107;
      pe_image_scn_type_no_pad=$00000008;
      pe_image_scn_cnt_code=$00000020;
      pe_image_scn_cnt_initialized_data=$00000040;
      pe_image_scn_cnt_uninitialized_data=$00000080;
      pe_image_scn_lnk_other=$00000100;
      pe_image_scn_lnk_info=$00000200;
      pe_image_scn_lnk_remove=$00000800;
      pe_image_scn_lnk_comdat=$00001000;
      pe_image_scn_gprel=$00008000;
      pe_image_scn_mem_purgeable=$00020000;
      pe_image_scn_mem_16bit=$00020000;
      pe_image_scn_mem_locked=$00040000;
      pe_image_scn_mem_preload=$00080000;
      pe_image_scn_align_1bytes=$00100000;
      pe_image_scn_align_2bytes=$00200000;
      pe_image_scn_align_4bytes=$00300000;
      pe_image_scn_align_8bytes=$00400000;
      pe_image_scn_align_16bytes=$00500000;
      pe_image_scn_align_32bytes=$00600000;
      pe_image_scn_align_64bytes=$00700000;
      pe_image_scn_align_128bytes=$00800000;
      pe_image_scn_align_256bytes=$00900000;
      pe_image_scn_align_512bytes=$00A00000;
      pe_image_scn_align_1024bytes=$00B00000;
      pe_image_scn_align_2048bytes=$00C00000;
      pe_image_scn_align_4096bytes=$00D00000;
      pe_image_scn_align_8192bytes=$00E00000;
      pe_image_scn_lnk_nreloc_ovfl=$01000000;
      pe_image_mem_discardable=$02000000;
      pe_image_mem_not_cached=$04000000;
      pe_image_mem_not_paged=$08000000;
      pe_image_mem_shared=$10000000;
      pe_image_mem_execute=$20000000;
      pe_image_mem_read=$40000000;
      pe_image_mem_write=$80000000;
      pe_image_rel_base_absolute=0;
      pe_image_rel_base_high=1;
      pe_image_rel_base_low=2;
      pe_image_rel_base_highlow=3;
      pe_image_rel_base_highadj=4;
      pe_image_rel_base_mips_jmpaddr=5;
      pe_image_rel_base_arm_mov32a=6;
      pe_image_rel_base_arm_mov32t=7;
      pe_image_rel_base_ia64_imm64=8;
      pe_image_rel_base_mips_jmpaddr16=9;
      pe_image_rel_base_dir64=10;
      {For RISC-V}
      pe_image_rel_base_riscv_hi20=5;
      pe_image_rel_base_riscv_low12i=7;
      pe_image_rel_base_riscv_low12s=8;
      {For LoongArch}
      pe_image_rel_base_loongarch32_mark_la=8;
      pe_image_rel_base_loongarch64_mark_la=8;
      {For DOS Stub Code}
      pe_dos_code:array[1..$40] of byte=($0E,$1F,$BA,$0E,$00,$B4,$09,$CD,$21,
      $B8,$01,$4C,$CD,$21,$54,$68,$69,$73,$20,$70,$72,$6F,$67,$72,$61,$6D,$20,$63,$61,$6E,$6E,$6F,
      $74,$20,$62,$65,$20,$72,$75,$6E,$20,$69,$6E,$20,$44,$4F,$53,$20,$6D,$6F,$64,$65,$2E,$0D,
      $0D,$0A,$24,$00,$00,$00,$00,$00,$00,$00);
      
type elf32_header=packed record 
                  elf32_identify:array[1..16] of byte;
                  elf32_type:word;
                  elf32_machine:word;
                  elf32_version:dword;
                  elf32_entry:dword;
                  elf32_program_header_offset:dword;
                  elf32_section_header_offset:dword;
                  elf32_flags:dword;
                  elf32_header_size:word;
                  elf32_program_header_size:word;
                  elf32_program_header_number:word;
                  elf32_section_header_size:word;
                  elf32_section_header_number:word;
                  elf32_section_header_string_table_index:word;
                  end;
     elf64_header=packed record
                  elf64_identify:array[1..16] of byte;
                  elf64_type:word;
                  elf64_machine:word;
                  elf64_version:dword;
                  elf64_entry:qword;
                  elf64_program_header_offset:qword;
                  elf64_section_header_offset:qword;
                  elf64_flags:dword;
                  elf64_header_size:word;
                  elf64_program_header_size:word;
                  elf64_program_header_number:word;
                  elf64_section_header_size:word;
                  elf64_section_header_number:word;
                  elf64_section_header_string_table_index:word;
                  end;
    elf_header=packed record
               case Boolean of
               True:(head32:elf32_header;);
               False:(head64:elf64_header;);
               end;
    elf32_section_header=packed record
                         section_header_name:dword;
                         section_header_type:dword;
                         section_header_flags:dword;
                         section_header_address:dword;
                         section_header_offset:dword;
                         section_header_size:dword;
                         section_header_link:dword;
                         section_header_info:dword;
                         section_header_address_align:dword;
                         section_header_entry_size:dword;
                         end;
    elf64_section_header=packed record
                         section_header_name:dword;
                         section_header_type:dword;
                         section_header_flags:qword;
                         section_header_address:qword;
                         section_header_offset:qword;
                         section_header_size:qword;
                         section_header_link:dword;
                         section_header_info:dword;
                         section_header_address_align:qword;
                         section_header_entry_size:qword;
                         end;
    elf_section_header=packed record
                       case Boolean of
                       True:(sec32:elf32_section_header;);
                       False:(sec64:elf64_section_header;);
                       end;
    Pelf_section_header=^elf_section_header;
    elf32_compression_header=packed record
                             compression_header_type:dword;
                             compression_header_size:dword;
                             compression_header_address_align:dword;
                             end;
    elf64_compression_header=packed record
                             compression_header_type:dword;
                             compression_header_reserved:dword;
                             compression_header_size:qword;
                             compression_header_address_align:qword;
                             end;
    elf_compression_header=packed record
                           case Boolean of
                           True:(c32:elf32_compression_header;);
                           False:(c64:elf64_compression_header;);
                           end;
    Pelf_compression_header=^elf_compression_header;
    elf32_symbol_header=packed record
                        symbol_table_name:dword;
                        symbol_table_value:dword;
                        symbol_table_size:dword;
                        symbol_table_info:byte;
                        symbol_table_other:byte;
                        symbol_table_string_table_index:word;
                        end;
    elf64_symbol_header=packed record
                        symbol_table_name:dword;
                        symbol_table_info:byte;
                        symbol_table_other:byte;
                        symbol_table_string_table_index:word;
                        symbol_table_value:qword;
                        symbol_table_size:qword;
                        end;
    elf_symbol_header=packed record
                      case Boolean of
                      True:(sym32:elf32_symbol_header;);
                      False:(sym64:elf64_symbol_header;);
                      end;
    Pelf_symbol_header=^elf_symbol_header;
    elf32_rel=packed record
              rel_offset:dword;
              rel_info:dword;
              end;
    elf32_rela=packed record
               rela_offset:dword;
               rela_info:dword;
               rela_addend:integer;
               end;
    Pelf32_rel=^elf32_rel;
    Pelf32_rela=^elf32_rela;
    elf32_rel_item=packed record
                   rel:Pelf32_rel;
                   count:dword;
                   end;
    Pelf32_rel_item=^elf32_rel_item;
    elf32_rel_list=packed record
                   item:Pelf32_rel_item;
                   count:dword;
                   end;
    elf32_rela_item=packed record
                    rela:Pelf32_rela;
                    count:dword;
                    end;
    Pelf32_rela_item=^elf32_rela_item;
    elf32_rela_list=packed record
                    item:Pelf32_rela_item;
                    count:dword;
                    end;
    elf64_rel=packed record
              rel_offset:qword;
              rel_info:qword;
              end;
    elf64_rela=packed record
               rela_offset:qword;
               rela_info:qword;
               rela_addend:int64;
               end;
    Pelf64_rel=^elf64_rel;
    Pelf64_rela=^elf64_rela;
    elf64_rel_item=packed record
                   rel:Pelf64_rel;
                   count:qword;
                   end;
    Pelf64_rel_item=^elf64_rel_item;
    elf64_rel_list=packed record
                   item:Pelf64_rel_item;
                   count:qword;
                   end;
    elf64_rela_item=packed record
                    rela:Pelf64_rela;
                    count:qword;
                    end;
    Pelf64_rela_item=^elf64_rela_item;
    elf64_rela_list=packed record
                    item:Pelf64_rela_item;
                    count:qword;
                    end;
    elf_rel_list=packed record
                 case Boolean of
                 True:(list32:elf32_rel_list;);
                 False:(list64:elf64_rel_list;);
                 end;
    elf_rela_list=packed record
                  case Boolean of
                  True:(list32:elf32_rela_list;);
                  False:(list64:elf64_rela_list;);
                  end;
    elf32_program_header=packed record
                         program_type:dword;
                         program_offset:dword;
                         program_virtual_address:dword;
                         program_physical_address:dword;
                         program_file_size:dword;
                         program_memory_size:dword;
                         program_flags:dword;
                         program_align:dword;
                         end;
    elf64_program_header=packed record
                         program_type:dword;
                         program_flags:dword;
                         program_offset:qword;
                         program_virtual_address:qword;
                         program_physical_address:qword;
                         program_file_size:qword;
                         program_memory_size:qword;
                         program_align:qword;
                         end;
    Pelf32_program_header=^elf32_program_header;
    Pelf64_program_header=^elf64_program_header;
    elf_program_header=packed record
                       case Boolean of
                       True:(pro32:elf32_program_header;);
                       False:(pro64:elf64_program_header;);
                       end;
    Pelf_program_header=^elf_program_header;
    elf32_dynamic_union=packed record
                        case Boolean of
                        True:(dynamic_value:dword;);
                        False:(dynamic_address:dword;);
                        end;
    elf32_dynamic=packed record
                  dynamic_tag:integer;
                  dynamic_union:elf32_dynamic_union;
                  end;
    elf64_dynamic_union=packed record
                        case Boolean of
                        True:(dynamic_value:qword;);
                        False:(dynamic_address:qword;);
                        end;
    elf64_dynamic=packed record
                  dynamic_tag:int64;
                  dynamic_union:elf64_dynamic_union;
                  end;
    elf_dynamic=packed record
                case Boolean of
                True:(dyn32:elf32_dynamic;);
                False:(dyn64:elf64_dynamic;);
                end;
    Pelf_dynamic=^elf_dynamic;
    elf_content=packed record
                case Byte of
                0:(ptr1:PByte;);
                1:(ptr2:Pword;);
                2:(ptr4:Pdword;);
                end;
    Pelf_content=^elf_content;
    elf_file=packed record
             bit:byte;
             header:elf_header;
             secheader:Pelf_section_header;
             seccontent:Pelf_content;
             proheader:Pelf_program_header;
             end;
    pe_image_dos_header=packed record
                        magic_number:word;
                        bytes_on_last_page_of_file:word;
                        pages_in_file:word;
                        relocations:word;
                        size_of_header_in_paragraphs:word;
                        minimum_extra_paragraphs_needed:word;
                        maximum_extra_paragraphs_needed:word;
                        initial_ss_value:word;
                        initial_sp_value:word;
                        checksum:word;
                        initial_ip_value:word;
                        initial_cs_value:word;
                        file_address_of_relocation_table:word;
                        overlay_number:word;
                        reserved:array[1..4] of word;
                        oem_identifier:word;
                        oem_infomation:word;
                        reserved2:array[1..10] of word;
                        file_address_of_new_exe_header:dword;
                        end;
    pe_image_file_header=packed record
                         Machine:word;
                         NumberOfSections:word;
                         TimeDateStamp:dword;
                         PointerToSymbolTable:dword;
                         NumberOfSymbols:dword;
                         SizeOfOptionalHeader:word;
                         Characteristics:word;
                         end;
    pe_image_data_directory=packed record
                            virtualaddress:dword;
                            Size:dword;
                            end;
    pe_image_nt_header32=packed record
                         Magic:word;
                         MajorLinkerVersion:byte;
                         MinorLinkerVersion:byte;
                         SizeOfCode:dword;
                         SizeOfInitializedData:dword;
                         SizeOfUninitializedData:dword;
                         AddressOfEntryPoint:dword;
                         BaseOfCode:dword;
                         BaseOfData:dword;
                         ImageBase:dword;
                         SectionAlignment:dword;
                         FileAlignment:dword;
                         MajorOperatingSystemVersion:word;
                         MinorOperatingSystemVersion:word;
                         MajorImageVersion:word;
                         MinorImageVersion:word;
                         MajorSubsystemVersion:word;
                         MinorSubsystemVersion:word;
                         Win32VersionValue:dword;
                         SizeOfImage:dword;
                         SizeOfHeaders:dword;
                         Checksum:dword;
                         Subsystem:word;
                         DllCharacteristics:word;
                         SizeOfStackReserve:dword;
                         SizeOfStackCommit:dword;
                         SizeOfHeapReserve:dword;
                         SizeOfHeapCommit:dword;
                         LoaderFlags:dword;
                         NumberOfRvaandSizes:dword;
                         DataDirectory:array[1..16] of pe_image_data_directory;
                         end;
    pe_image_nt_header64=packed record
                         Magic:word;
                         MajorLinkerVersion:byte;
                         MinorLinkerVersion:byte;
                         SizeOfCode:dword;
                         SizeOfInitializedData:dword;
                         SizeOfUninitializedData:dword;
                         AddressOfEntryPoint:dword;
                         BaseOfCode:dword;
                         ImageBase:qword;
                         SectionAlignment:dword;
                         FileAlignment:dword;
                         MajorOperatingSystemVersion:word;
                         MinorOperatingSystemVersion:word;
                         MajorImageVersion:word;
                         MinorImageVersion:word;
                         MajorSubsystemVersion:word;
                         MinorSubsystemVersion:word;
                         Win32VersionValue:dword;
                         SizeOfImage:dword;
                         SizeOfHeaders:dword;
                         Checksum:dword;
                         Subsystem:word;
                         DllCharacteristics:word;
                         SizeOfStackReserve:qword;
                         SizeOfStackCommit:qword;
                         SizeOfHeapReserve:qword;
                         SizeOfHeapCommit:qword;
                         LoaderFlags:dword;
                         NumberOfRvaandSizes:dword;
                         DataDirectory:array[1..16] of pe_image_data_directory;
                         end;
     pe_image_header=packed record
                     Signature:dword;
                     FileHeader:pe_image_file_header;
                     case Boolean of
                     True:(OptionalHeader:pe_image_nt_header32;);
                     False:(OptionalHeader64:pe_image_nt_header64;);
                     end;
     pe_misc_union=packed record 
                   case Boolean of 
                   True:(PhysicalAddress:dword;);
                   False:(VirtualSize:dword;);
                   end;
     pe_image_section_header=packed record
                             Name:array[1..8] of char;
                             Misc:pe_misc_union;
                             VirtualAddress:dword;
                             SizeOfRawData:dword;
                             PointerToRawData:dword;
                             PointerToRelocation:dword;
                             PointerToLineNumbers:dword;
                             NumberOfRelocations:word;
                             NumberOfLineNumbers:word;
                             Characteristics:dword;
                             end;
     Ppe_image_section_header=^pe_image_section_header;
     pe_dummy_union_name=packed record
                         case Boolean of
                         True:(Characteristics:dword);
                         False:(OriginalFirstThunk:dword);
                         end;
     pe_image_import_descriptor=packed record 
                                DummyUnionName:pe_dummy_union_name;
                                TimeDateStamp:dword;
                                ForwarderChain:dword;
                                Name:dword;
                                FirstThunk:dword;
                                end;
     pe_image_bound_import_descriptor=packed record
                                      TimeDateStamp:dword;
                                      OffsetModuleName:word;
                                      NumberOfModuleForwarderRefs:word;
                                      end;
     pe_image_import_by_name=packed record
                             hint:word;
                             name:dword;
                             end;
     pe_image_type_offset=bitpacked record
                         Offset:0..4095;
                         peType:0..15;
                         end;
     Ppe_image_type_offset=^pe_image_type_offset;
     pe_image_base_relocation=packed record
                              VirtualAddress:dword;
                              SizeOfBlock:dword;
                              end;
     Ppe_image_base_relocation=^pe_image_base_relocation;
     pe_base_relocation_item=packed record
                             base:pe_image_base_relocation;
                             reloc:Ppe_image_type_offset;
                             count:word;
                             end;
     Ppe_base_relocation_item=^pe_base_relocation_item;
     pe_base_relocation_list=packed record
                             item:Ppe_base_relocation_item;
                             count:word;
                             end;
     pe_content=packed record
                case Byte of
                0:(ptr1:PByte;);
                1:(ptr2:Pword;);
                2:(ptr4:Pdword;);
                end;
     Ppe_content=^pe_content;
     pe_file=packed record
             bit:byte;
             dosheader:pe_image_dos_header;
             dosstub:Pbyte;
             dosstubsize:byte;
             imageheader:pe_image_header;
             secheaderaddress:qword;
             secheader:Ppe_image_section_header;
             seccontentaddress:qword;
             seccontent:Ppe_content;
             end;

function elf_least_byte_to_most_byte(lsb:word):word;
function elf_least_byte_to_most_byte(lsb:dword):dword;
function elf_least_byte_to_most_byte(lsb:qword):qword;
function elf_most_byte_to_least_byte(msb:word):word;
function elf_most_byte_to_least_byte(msb:dword):dword;
function elf_most_byte_to_least_byte(msb:qword):qword;
function elf_symbol_table_bind(i:byte):byte;
function elf_symbol_table_type(i:byte):byte;
function elf_symbol_table_info(b,t:byte):byte;
function elf_symbol_table_visibility(o:byte):byte;
function elf32_relocation_symbol(i:dword):dword;
function elf32_relocation_type(i:dword):dword;
function elf32_relocation_info(s,t:dword):dword;
function elf64_relocation_symbol(i:qword):qword;
function elf64_relocation_type(i:qword):qword;
function elf64_relocation_info(s,t:qword):qword;
procedure pe_move_dos_code_to_dos_stub(const Source;var dest);

implementation
function elf_least_byte_to_most_byte(lsb:word):word;
begin
 elf_least_byte_to_most_byte:=(lsb shr 8) and $00FF+(lsb shl 8) and $FF00;
end;
function elf_least_byte_to_most_byte(lsb:dword):dword;
begin
 elf_least_byte_to_most_byte:=(lsb shr 24) and $000000FF+(lsb shr 8) and $0000FF00+
 (lsb shl 8) and $00FF0000+(lsb shl 24) and $FF000000;
end;
function elf_least_byte_to_most_byte(lsb:qword):qword;
begin
 elf_least_byte_to_most_byte:=(lsb shr 56) and $00000000000000FF
 +(lsb shr 40) and $000000000000FF00+(lsb shr 24) and $0000000000FF0000
 +(lsb shr 8) and $00000000FF000000+(lsb shl 8) and $000000FF00000000
 +(lsb shl 24) and $0000FF0000000000+(lsb shl 40) and $00FF000000000000
 +(lsb shl 56) and $FF00000000000000;
end;
function elf_most_byte_to_least_byte(msb:word):word;
begin
 elf_most_byte_to_least_byte:=(msb shr 8) and $00FF+(msb shl 8) and $FF00;
end;
function elf_most_byte_to_least_byte(msb:dword):dword;
begin
 elf_most_byte_to_least_byte:=(msb shr 24) and $000000FF+(msb shr 8) and $0000FF00+
 (msb shl 8) and $00FF0000+(msb shl 24) and $FF000000;
end;
function elf_most_byte_to_least_byte(msb:qword):qword;
begin
 elf_most_byte_to_least_byte:=(msb shr 56) and $00000000000000FF
 +(msb shr 40) and $000000000000FF00+(msb shr 24) and $0000000000FF0000
 +(msb shr 8) and $00000000FF000000+(msb shl 8) and $000000FF00000000
 +(msb shl 24) and $0000FF0000000000+(msb shl 40) and $00FF000000000000
 +(msb shl 56) and $FF00000000000000;
end;
function elf_symbol_table_bind(i:byte):byte;
begin
 elf_symbol_table_bind:=i shr 4;
end;
function elf_symbol_table_type(i:byte):byte;
begin
 elf_symbol_table_type:=i and $F;
end;
function elf_symbol_table_info(b,t:byte):byte;
begin
 elf_symbol_table_info:=b shl 4+t and $F;
end;
function elf_symbol_table_visibility(o:byte):byte;
begin
 elf_symbol_table_visibility:=o and $3;
end;
function elf32_relocation_symbol(i:dword):dword;
begin
 elf32_relocation_symbol:=i shr 8;
end;
function elf32_relocation_type(i:dword):dword;
begin
 elf32_relocation_type:=Byte(i);
end;
function elf32_relocation_info(s,t:dword):dword;
begin
 elf32_relocation_info:=s shl 8+Byte(t);
end;
function elf64_relocation_symbol(i:qword):qword;
begin
 elf64_relocation_symbol:=i shr 32;
end;
function elf64_relocation_type(i:qword):qword;
begin 
 elf64_relocation_type:=i and $FFFFFFFF;
end;
function elf64_relocation_info(s,t:qword):qword;
begin 
 elf64_relocation_info:=s shl 32+t and $FFFFFFFF;
end;
procedure pe_move_dos_code_to_dos_stub(const Source;var dest);
var i:byte;
begin
 for i:=1 to $40 do PByte(@dest+i-1)^:=PByte(@source+i-1)^;
end;

end.
