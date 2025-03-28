program elf2efi;

{$mode ObjFPC}

uses sysutils,binarybase,convbase;

var elffile:elf_file;
    pefile:pe_file;
    outputfn,outputpath:string;
    i:SizeUint;

begin
 writeln('elf2efi(elf file to efi file converter) alpha v0.0.1');
 if(ParamCount<2) or (ParamCount>3) then
  begin
   if(ParamCount<1) then writeln('elf2efi:no command,show the help.')
   else if(ParamCount<2) then writeln('elf2efi:too few command,show the help.')
   else if(ParamCount>3) then writeln('elf2efi:too many command,show the help.');
   writeln('Template:elf2efi [input file name] [output file name] [output file type(optional)]');
   writeln('Vaild output file type:UEFI_APPLICATION/EFIAPP');
   writeln('                       UEFI_BOOT_DRIVER/EFIBOOTDRV');
   writeln('                       UEFI_RUNTIME_DRIVER/EFIRUNDRV');
   writeln('                       If you don'#39't input the output file type,default is EFIAPP.');
   writeln('Supported Architecture:x86,amd64,arm,aarch64,riscv32,riscv64,loongarch32,loongarch64');
   writeln('Any other architecture is not UEFI supported architecture,so don'#39't type in it.');
   readln;
   exit;
  end
 else
  begin
   conv_heap_initialize;
   if(FileExists(paramStr(1))) then
    begin
     writeln('Trying the read the content of elf file......');
     elffile:=conv_read_elf(paramStr(1));
     writeln('ELF file readed successfully!');
    end
   else
    begin
     writeln('ERROR:File '+ParamStr(1)+' not found.');
     readln;
     abort;
    end;
   i:=length(ParamStr(2)); outputfn:=ParamStr(2);
   while(i>0)do
    begin
     if(outputfn[i]='/') or (outputfn[i]='\') then break;
     dec(i);
    end;
   if(i>0) then outputpath:=Copy(outputfn,1,i-1) else outputpath:='';
   if(outputpath<>'') and (DirectoryExists(outputpath)=false) then
    begin
     writeln('ERROR:Output path does not exist.');
     readln;
     abort;
    end;
   if(ParamCount=2) then
    begin
     writeln('Trying to generate the content of efi file......');
     pefile:=conv_elf_to_efi(elffile,pe_image_subsystem_efi_application);
    end
   else if(LowerCase(ParamStr(3))='efiapp') or (LowerCase(ParamStr(3))='uefi_application') then
    begin
     writeln('Trying to generate the content of efi file......');
     pefile:=conv_elf_to_efi(elffile,pe_image_subsystem_efi_application);
    end
   else if(LowerCase(ParamStr(3))='efibootdrv') or (LowerCase(ParamStr(3))='uefi_boot_driver') then
    begin
     writeln('Trying to generate the content of efi file......');
     pefile:=conv_elf_to_efi(elffile,pe_image_subsystem_efi_boot_service_driver);
    end
   else if(LowerCase(ParamStr(3))='efirundrv') or (LowerCase(ParamStr(3))='uefi_runtime_driver') then
    begin
     writeln('Trying to generate the content of efi file......');
     pefile:=conv_elf_to_efi(elffile,pe_image_subsystem_efi_runtime_driver);
    end
   else
    begin
     writeln('ERROR:Unrecogized type '+ParamStr(3)+'.');
     readln;
     abort;
    end;
   writeln('Write the efi file......');
   conv_efi_write(pefile,outputfn);
   writeln('EFI file generated!');
   conv_elf_free(elffile);
   conv_pe_free(pefile);
   writeln('ELF file '+ParamStr(1)+' was successfully converted to EFI file '+ParamStr(2)+',Command Done!');
   conv_heap_finalize;
  end;
end.

