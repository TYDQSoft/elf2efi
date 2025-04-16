unit convbase;

{$mode ObjFPC}

interface

uses Classes,SysUtils,binarybase,convmem;

type file_section_list=packed record
                       secindex:Pword;
                       seccount:byte;
                       end;
     file_relative_offset=packed record
                          baseaddr:SizeUint;
                          offset:SizeUint;
                          end;

function conv_read_elf(fn:string):elf_file;
function conv_elf_to_efi(elf:elf_file;apptype:byte):pe_file;
procedure conv_efi_write(efi:pe_file;fn:string);
procedure conv_elf_free(var elf:elf_file);
procedure conv_pe_free(var pe:pe_file);
procedure conv_heap_initialize;
procedure conv_heap_finalize;

implementation

procedure conv_io_read(fn:string;var dest;offset,size:SizeUint);
var f:TFileStream;
    i:SizeUint;
begin
 f:=TFileStream.Create(fn,fmOpenRead);
 f.Seek(offset,0);
 if(size-size shr 3 shl 3=0) then
  begin
   for i:=1 to size shr 3 do f.Read(Pqword(Pointer(@dest)+(i-1) shl 3)^,8);
  end
 else if(size-size shr 2 shl 2=0) then
  begin
   for i:=1 to size shr 2 do f.Read(Pdword(Pointer(@dest)+(i-1) shl 2)^,4);
  end
 else if(size-size shr 1 shl 1=0) then
  begin
   for i:=1 to size shr 1 do f.Read(Pword(Pointer(@dest)+(i-1) shl 1)^,2);
  end
 else
  begin
   for i:=1 to size do f.Read(PByte(Pointer(@dest)+i-1)^,1);
  end;
 f.Free;
end;
procedure conv_io_write(fn:string;const source;offset,size:SizeUint);
var f:TFileStream;
    i:SizeUint;
begin
 if(FileExists(fn)) then f:=TFileStream.Create(fn,fmOpenWrite) else f:=TFileStream.Create(fn,fmCreate);
 f.Seek(offset,0);
 if(size-size shr 3 shl 3=0) then
  begin
   for i:=1 to size shr 3 do f.Write(Pqword(Pointer(@source)+(i-1) shl 3)^,8);
  end
 else if(size-size shr 2 shl 2=0) then
  begin
   for i:=1 to size shr 2 do f.Write(Pdword(Pointer(@source)+(i-1) shl 2)^,4);
  end
 else if(size-size shr 1 shl 1=0) then
  begin
   for i:=1 to size shr 1 do f.Write(Pword(Pointer(@source)+(i-1) shl 1)^,2);
  end
 else
  begin
   for i:=1 to size do f.Write(Pbyte(Pointer(@source)+i-1)^,1);
  end;
 f.Free;
end;
function conv_check_elf_header(fn:string):boolean;
var checkbyte:array[1..16] of byte;
    i:byte;
begin
 conv_io_read(fn,checkbyte,0,16);
 i:=1;
 while(i<=4)do
  begin
   if(checkbyte[i]<>elf_file_identify[i]) then break;
   inc(i);
  end;
 if(i>4) then Result:=true else Result:=false;
end;
procedure conv_heap_initialize;
var ptr:Pointer;
begin
 ptr:=allocmem(1024*1024*512);
 memheap:=heap_initialize(SizeUint(ptr),SizeUint(ptr+1024*1024*512-1),4);
end;
function conv_allocmem(Size:SizeUint):Pointer;
begin
 conv_allocmem:=tydq_allocmem(Size);
end;
function conv_reallocmem(var ptr:Pointer;Size:SizeUint):Pointer;
begin
 conv_reallocmem:=tydq_reallocmem(ptr,Size);
end;
procedure conv_freemem(var ptr:Pointer);
begin
 tydq_freemem(ptr);
end;
procedure conv_move(const Source;Var Dest;Size:SizeUint);
begin
 tydq_move(source,dest,size);
end;
procedure conv_heap_finalize;
begin
 FreeMem(memheap.mem_start);
end;
function conv_read_elf(fn:string):elf_file;
var checkbyte:array[1..16] of byte;
    contentoffset,contentsize,j:SizeUint;
    i:word;
begin
 if(conv_check_elf_header(fn)=false) then
  begin
   writeln('ERROR:It is not elf file,program terminated.');
   readln;
   abort;
  end;
 conv_io_read(fn,checkbyte,0,16);
 if(checkbyte[elf_class_pos]=elf_class_none) then
  begin
   writeln('ERROR:Elf Class is not specified.');
   readln;
   abort;
  end
 else if(checkbyte[elf_class_pos]=elf_class_32) then
  begin
   Result.bit:=32; conv_io_read(fn,Result.header.head32,0,sizeof(elf32_header));
   if(Result.header.head32.elf32_type<>elf_type_executable) and
   (Result.header.head32.elf32_type<>elf_type_dynamic) then
    begin
     writeln('ERROR:Elf file type is not executable or library.');
     readln;
     abort;
    end;
   if(Result.header.head32.elf32_machine<>elf_machine_386)
   and(Result.header.head32.elf32_machine<>elf_machine_arm)
   and(Result.header.head32.elf32_machine<>elf_machine_riscv)
   and(Result.header.head32.elf32_machine<>elf_machine_loongarch) then
    begin
     writeln('ERROR:Architecture of elf file is unsupported.');
     readln;
     abort;
    end;
   Result.secheader:=conv_allocmem(Result.header.head32.elf32_section_header_number*sizeof(elf_section_header));
   Result.seccontent:=conv_allocmem(Result.header.head32.elf32_section_header_number*sizeof(elf_content));
   i:=1;
   while(i<=Result.header.head32.elf32_section_header_number)do
    begin
     conv_io_read(fn,Pelf_section_header(Result.secheader+i-1)^.sec32,
     Result.header.head32.elf32_section_header_offset+(i-1)*sizeof(elf32_section_header),
     sizeof(elf32_section_header));
     if(Pelf_section_header(Result.secheader+i-1)^.sec32.section_header_size>0)
     and(Pelf_section_header(Result.secheader+i-1)^.sec32.section_header_type<>
     elf_section_header_nobits) then
      begin
       contentoffset:=Pelf_section_header(Result.secheader+i-1)^.sec32.section_header_offset;
       contentsize:=Pelf_section_header(Result.secheader+i-1)^.sec32.section_header_size;
       Pelf_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(contentsize);
       for j:=1 to contentsize do
         begin
          conv_io_read(fn,(Pelf_content(Result.seccontent+i-1)^.ptr1+j-1)^,
          contentoffset+j-1,1);
         end;
      end
     else if(Pelf_section_header(Result.secheader+i-1)^.sec32.section_header_size>0)
     and(Pelf_section_header(Result.secheader+i-1)^.sec32.section_header_type=
     elf_section_header_nobits) then
      begin
       contentoffset:=Pelf_section_header(Result.secheader+i-1)^.sec32.section_header_offset;
       contentsize:=Pelf_section_header(Result.secheader+i-1)^.sec32.section_header_size;
       Pelf_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(contentsize);
      end
     else Pelf_content(Result.seccontent+i-1)^.ptr1:=nil;
     inc(i);
    end;
   Result.proheader:=nil;
  end
 else if(checkbyte[elf_class_pos]=elf_class_64) then
  begin
   Result.bit:=64; conv_io_read(fn,Result.header.head64,0,sizeof(elf64_header));
   if(Result.header.head64.elf64_type<>elf_type_executable) and
   (Result.header.head64.elf64_type<>elf_type_dynamic) then
    begin
     writeln('ERROR:Elf file type is not executable or library.');
     readln;
     abort;
    end;
   if(Result.header.head64.elf64_machine<>elf_machine_x86_64)
   and(Result.header.head64.elf64_machine<>elf_machine_aarch64)
   and(Result.header.head64.elf64_machine<>elf_machine_riscv)
   and(Result.header.head64.elf64_machine<>elf_machine_loongarch)then
    begin
     writeln('ERROR:Architecture of elf file is unsupported.');
     readln;
     abort;
    end;
   Result.secheader:=conv_allocmem(Result.header.head64.elf64_section_header_number*sizeof(elf_section_header));
   Result.seccontent:=conv_allocmem(Result.header.head64.elf64_section_header_number*sizeof(elf_content));
   i:=1;
   while(i<=Result.header.head64.elf64_section_header_number)do
    begin
     conv_io_read(fn,Pelf_section_header(Result.secheader+i-1)^.sec64,
     Result.header.head64.elf64_section_header_offset+(i-1)*sizeof(elf64_section_header),
     sizeof(elf64_section_header));
     if(Pelf_section_header(Result.secheader+i-1)^.sec64.section_header_size>0)
     and(Pelf_section_header(Result.secheader+i-1)^.sec64.section_header_type<>
     elf_section_header_nobits) then
      begin
       contentoffset:=Pelf_section_header(Result.secheader+i-1)^.sec64.section_header_offset;
       contentsize:=Pelf_section_header(Result.secheader+i-1)^.sec64.section_header_size;
       Pelf_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(contentsize);
       for j:=1 to contentsize do
        begin
         conv_io_read(fn,(Pelf_content(Result.seccontent+i-1)^.ptr1+j-1)^,
         contentoffset+j-1,1);
        end;
      end
     else if(Pelf_section_header(Result.secheader+i-1)^.sec64.section_header_size>0)
     and(Pelf_section_header(Result.secheader+i-1)^.sec64.section_header_type=
     elf_section_header_nobits) then
      begin
       contentoffset:=Pelf_section_header(Result.secheader+i-1)^.sec64.section_header_offset;
       contentsize:=Pelf_section_header(Result.secheader+i-1)^.sec64.section_header_size;
       Pelf_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(contentsize);
      end
     else Pelf_content(Result.seccontent+i-1)^.ptr1:=nil;
     inc(i);
    end;
   Result.proheader:=nil;
  end;
 writeln('elf file loaded to memory!');
end;
function conv_get_elf_section_name(elf:elf_file;index:SizeUint):PChar;
var i,len:SizeUint;
    ptr:PChar;
begin
 Result:=conv_allocmem(1); len:=0;
 if(elf.bit=32) then
  begin
   i:=Pelf_section_header(elf.secheader+index-1)^.sec32.section_header_name;
   ptr:=PChar(Pelf_content(
   elf.seccontent+elf.header.head32.elf32_section_header_string_table_index)^.ptr1);
   while((ptr+i-1)^<>#0)do
    begin
     inc(len);
     conv_reallocmem(Result,len+1);
     (Result+len-1)^:=(ptr+i-1)^;
     inc(i);
    end;
   (Result+len)^:=#0;
  end
 else if(elf.bit=64) then
  begin
   i:=Pelf_section_header(elf.secheader+index-1)^.sec64.section_header_name;
   ptr:=PChar(Pelf_content(
   elf.seccontent+elf.header.head64.elf64_section_header_string_table_index)^.ptr1);
   while((ptr+i-1)^<>#0)do
    begin
     inc(len);
     conv_reallocmem(Result,len+1);
     (Result+len-1)^:=(ptr+i-1)^;
     inc(i);
    end;
   (Result+len)^:=#0;
  end;
end;
function conv_generate_crc32(buf:PByte;buflen:Dword;checksum:Dword):Dword;
var sum,csum,len:dword;
    dataptr:Pbyte;
begin
 if(buflen and Dword(buf)<>0) then
  begin
   sum:=0; csum:=checksum; dataptr:=buf; len:=buflen;
   repeat
    sum:=(Pword(dataptr)^+csum) and $FFFFFFFF;
    csum:=(Word(sum)+sum shr 16) and $FFFFFFFF;
    inc(dataptr,2);
    dec(len);
   until(len=0);
   Result:=(csum+csum shr 16);
  end
 else Result:=(checksum+checksum shr 16) and $FFFFFFFF;
end;
function conv_generate_timestamp:dword;
const monthdata1:array[1..12] of byte=(31,28,31,30,31,30,31,31,30,31,30,31);
      monthdata2:array[1..12] of byte=(31,29,31,30,31,30,31,31,30,31,30,31);
var tempres:TSystemTime;
    i,j:word;
    bool:boolean;
begin
 DateTimeToSystemTime(Now,tempres);
 i:=1970; Result:=0;
 while(i<=tempres.Year)do
  begin
   if(i<tempres.Year) then
    begin
     if(tempres.Year mod 4=0) then
      begin
       if(tempres.Year mod 100=0) and (tempres.Year mod 400=0) then
       inc(Result,366*24*60*60)
       else if(tempres.Year mod 100<>0) then
       inc(Result,366*24*60*60)
       else
       inc(Result,365*24*60*60)
      end
     else inc(Result,365*24*60*60);
    end
   else
    begin
     j:=1; bool:=false;
     if(tempres.Year mod 4=0) then
      begin
       if(tempres.Year mod 100=0) and (tempres.Year mod 400=0) then bool:=true
       else if(tempres.Year mod 100<>0) then bool:=true
       else bool:=false;
      end
     else bool:=false;
     if(bool=true) then
      begin
       while(j<=tempres.Month)do
        begin
         if(j<tempres.Month) then
          begin
           inc(Result,monthdata1[j]*24*60*60);
          end
         else
          begin
           inc(Result,(tempres.Day-1)*24*60*60+(tempres.Hour-1)*60*60+(tempres.Minute-1)*60+tempres.Second-1);
          end;
         inc(j);
        end;
      end
     else
      begin
       while(j<=tempres.Month)do
        begin
         if(j<tempres.Month) then
          begin
           inc(Result,monthdata2[j]*24*60*60);
          end
         else
          begin
           inc(Result,(tempres.Day-1)*24*60*60+(tempres.Hour-1)*60*60+(tempres.Minute-1)*60+tempres.Second-1);
          end;
         inc(j);
        end;
      end;
    end;
   inc(i);
  end;
end;
function conv_efi_to_buffer(efi:pe_file;efiSize:SizeUint):PByte;
var buf:Pbyte=nil;
    i,size,writepos:SizeUint;
begin
 buf:=conv_allocmem(efiSize);
 writepos:=0;
 conv_move(efi.dosheader,buf^,sizeof(pe_image_dos_header));
 writepos:=sizeof(pe_image_dos_header);
 i:=1;
 while(i<=efi.dosstubsize shr 3)do
  begin
   Pqword(buf+writepos+(i-1) shl 3)^:=Pqword(efi.dosstub+(i-1) shl 3)^;
   inc(i);
  end;
 inc(writepos,efi.dosstubsize);
 conv_move(efi.Imageheader.Signature,(buf+writepos)^,sizeof(dword));
 inc(writepos,sizeof(dword));
 conv_move(efi.imageheader.FileHeader,(buf+writepos)^,sizeof(pe_image_file_header));
 inc(writepos,sizeof(pe_image_file_header));
 if(efi.bit=32) then
 conv_move(efi.imageheader.OptionalHeader,(buf+writepos)^,sizeof(pe_image_nt_header32))
 else if(efi.bit=64) then
 conv_move(efi.imageheader.OptionalHeader64,(buf+writepos)^,sizeof(pe_image_nt_header64));
 writepos:=efi.secheaderaddress;
 conv_move(efi.secheader^,(buf+writepos)^,sizeof(pe_image_section_header)*
 efi.Imageheader.FileHeader.NumberOfSections);
 writepos:=efi.seccontentaddress;
 i:=1;
 while(i<=efi.Imageheader.FileHeader.NumberOfSections)do
  begin
   size:=Ppe_image_section_header(efi.secheader+i-1)^.SizeOfRawData;
   writepos:=Ppe_image_section_header(efi.secheader+i-1)^.PointerToRawData;
   conv_move(Ppe_content(efi.seccontent+i-1)^.ptr1^,(buf+writepos)^,size);
   inc(i);
  end;
 Result:=buf;
end;
function conv_get_efi_relative_offset(elftextoffset,elfrodataoffset,elfdataoffset:SizeUint;
petextoffset,perodataoffset,pedataoffset:SizeUint;
addrneedlocate:SizeUint):file_relative_offset;
begin
 if(elfrodataoffset<>0) then
  begin
   if(addrneedlocate<=elfrodataoffset) then
    begin
     Result.baseaddr:=petextoffset; Result.offset:=addrneedlocate-elftextoffset;
    end
   else if(addrneedlocate<=elfdataoffset) then
    begin
     Result.baseaddr:=perodataoffset; Result.offset:=addrneedlocate-elfrodataoffset;
    end
   else
    begin
     Result.baseaddr:=pedataoffset; Result.offset:=addrneedlocate-elfdataoffset;
    end;
  end
 else
  begin
   if(addrneedlocate<=elfdataoffset) then
    begin
     Result.baseaddr:=petextoffset; Result.offset:=addrneedlocate-elftextoffset;
    end
   else
    begin
     Result.baseaddr:=pedataoffset; Result.offset:=addrneedlocate-elfdataoffset;
    end;
  end;
end;
function conv_elf_to_efi(elf:elf_file;apptype:byte):pe_file;
var entrystart,highaddress,addralign:SizeUint;
    elftextaddress,elfrodataaddress,elfdataaddress:SizeUint;
    petextaddress,perodataaddress,pedataaddress,perelocaddress:SizeUint;
    rela:elf_rela_list;
    havetext,haverodata,havedata:boolean;
    textlist,rodatalist,datalist:file_section_list;
    i,j,k:SizeUint;
    breloclist:pe_base_relocation_list;
    relocsize:SizeUint;
    efiseccount:byte;
    tempaddress1,tempaddress2:SizeUint;
    tempsize:SizeUint;
    newoffset,newaddend,baseoffset,typeoffsetcount:SizeUint;
    writeoffset,writeptr:SizeUint;
    efibuf:PByte;
    {For Offset in elf file}
    elffiletextstart,elffiletextend:SizeUint;
    elffilerodatastart,elffilerodataend:SizeUint;
    elffiledatastart,elffiledataend:SizeUint;
    pefiletextoffset,pefilerodataoffset,pefiledataoffset,pefilerelocoffset:SizeUint;
    {For File Relative Offset}
    peRelaoffset:file_relative_offset;
    {For File Size}
    peFileSize:SizeUint;
    {For ELF File to PE File Comparsion}
    islower:boolean;
begin
 {Initialize the file offset}
 elffiletextstart:=0; elffiletextend:=0;
 elffilerodatastart:=0; elffilerodataend:=0;
 elffiledatastart:=0; elffiledataend:=0;
 {Initialize the used variables}
 elftextaddress:=0; elfrodataaddress:=0; elfdataaddress:=0;
 havetext:=false; haverodata:=false; havedata:=false;
 textlist.seccount:=0; rodatalist.seccount:=0; datalist.seccount:=0;
 textlist.secindex:=nil; rodatalist.secindex:=nil; datalist.secindex:=nil;
 petextaddress:=0; perodataaddress:=0; pedataaddress:=0; perelocaddress:=0;
 pefiletextoffset:=0; pefilerodataoffset:=0; pefiledataoffset:=0; pefilerelocoffset:=0;
 baseoffset:=0;
 {Initialize the PE header}
 for i:=1 to sizeof(pe_file) do PByte(Pointer(@Result)+i-1)^:=0;
 Result.dosheader.magic_number:=$5A4D;
 Result.dosheader.file_address_of_new_exe_header:=sizeof(pe_image_dos_header)+$40;
 Result.dosstub:=conv_allocmem($40);
 pe_move_dos_code_to_dos_stub(pe_dos_code,Result.dosstub^);
 Result.dosstubsize:=$40;
 Result.imageheader.Signature:=$00004550;
 entrystart:=0; highaddress:=0; addralign:=0;
 {Collect any elf file info used after parsing}
 Result.bit:=elf.bit;
 if(elf.bit=32) then
  begin
   rela.list32.count:=0; rela.list32.item:=nil;
   entrystart:=elf.header.head32.elf32_entry;
   i:=2;
   while(i<=elf.header.head32.elf32_section_header_number)do
    begin
     if(Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_flags=
     elf_section_header_flag_exec_instr or elf_section_header_flag_alloc) and (havetext=false) then
      begin
       elftextaddress:=Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_address;
       elffiletextstart:=elftextaddress;
       havetext:=true;
      end
     else if(Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_flags=
     elf_section_header_flag_alloc) and (havetext) and (haverodata=false) then
      begin
       elfrodataaddress:=Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_address;
       elffilerodatastart:=elfrodataaddress;
       haverodata:=true;
      end
     else if(Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_flags=
     elf_section_header_flag_alloc or elf_section_header_flag_write)
     and (havetext) and (havedata=false) then
      begin
       elfdataaddress:=Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_address;
       elffiledatastart:=elfdataaddress;
       havedata:=true;
      end;
     if(Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_flags=
     elf_section_header_flag_exec_instr or elf_section_header_flag_alloc) and (havetext)
     and (haverodata=false) and (havedata=false) then
      begin
       inc(textlist.seccount);
       conv_reallocmem(textlist.secindex,textlist.seccount*2);
       elffiletextend:=Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_address
       +Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_size;
       (textlist.secindex+textlist.seccount-1)^:=i;
      end
     else if(Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_flags=
     elf_section_header_flag_alloc) and (havetext) and (haverodata) then
      begin
       inc(rodatalist.seccount);
       conv_reallocmem(rodatalist.secindex,rodatalist.seccount*2);
       elffilerodataend:=Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_address
       +Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_size;
       (rodatalist.secindex+rodatalist.seccount-1)^:=i;
      end
     else if(Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_flags=
     elf_section_header_flag_write or elf_section_header_flag_alloc) and (havetext)
     and (havedata) then
      begin
       inc(datalist.seccount);
       conv_reallocmem(datalist.secindex,datalist.seccount*2);
       elffiledataend:=Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_address
       +Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_size;
       (datalist.secindex+datalist.seccount-1)^:=i;
      end;
     if(Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_address
     +Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_size>highaddress)
     and(Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_flags and
     elf_section_header_flag_alloc=elf_section_header_flag_alloc) and (havetext) then
     highaddress:=Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_address
     +Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_size;
     if(Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_flags and
     elf_section_header_flag_alloc=elf_section_header_flag_alloc) and
     (Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_address_align>addralign) then
      begin
       addralign:=Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_address_align;
      end;
     if(Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_type=elf_section_header_rela) then
      begin
       inc(rela.list32.count); conv_reallocmem(rela.list32.item,rela.list32.count*sizeof(elf32_rela_item));
       Pelf32_rela_item(rela.list32.item+rela.list32.count-1)^.rela:=
       conv_allocmem(Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_size);
       Pelf32_rela_item(rela.list32.item+rela.list32.count-1)^.count:=
       Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_size div
       Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_entry_size;
       conv_move(Pelf_content(elf.seccontent+i-1)^.ptr1^,
       Pelf32_rela_item(rela.list32.item+rela.list32.count-1)^.rela^,
       Pelf_section_header(elf.secheader+i-1)^.sec32.section_header_size);
      end;
     inc(i);
    end;
   Result.imageheader.FileHeader.NumberOfSections:=Byte(havetext)+Byte(haverodata)+Byte(havedata)+1;
   efiseccount:=Result.imageheader.FileHeader.NumberOfSections;
   Result.imageheader.FileHeader.NumberOfSymbols:=0;
   Result.imageheader.FileHeader.PointerToSymbolTable:=0;
   Result.imageheader.FileHeader.SizeOfOptionalHeader:=sizeof(pe_image_nt_header32);
   Result.imageheader.FileHeader.Characteristics:=
   pe_image_file_executable_image or pe_image_file_line_nums_stripped
   or pe_image_file_local_syms_stripped or pe_image_file_debug_stripped or pe_image_file_large_address_aware;
   Result.imageheader.FileHeader.TimeDateStamp:=conv_generate_timestamp;
   if(elf.header.head32.elf32_machine=elf_machine_386) then
    begin
     Result.imageheader.FileHeader.Machine:=pe_image_file_machine_i386;
    end
   else if(elf.header.head32.elf32_machine=elf_machine_arm) then
    begin
     Result.imageheader.FileHeader.Machine:=pe_image_file_machine_arm;
    end
   else if(elf.header.head32.elf32_machine=elf_machine_riscv) then
    begin
     Result.imageheader.FileHeader.Machine:=pe_image_file_machine_riscv32;
    end
   else if(elf.header.head32.elf32_machine=elf_machine_loongarch) then
    begin
     Result.imageheader.FileHeader.Machine:=pe_image_file_machine_loongarch32;
    end;
   Result.secheaderaddress:=sizeof(pe_image_dos_header)+Result.dosstubsize+sizeof(dword)+
   sizeof(pe_image_file_header)+sizeof(pe_image_nt_header32);
   Result.secheader:=conv_allocmem(sizeof(pe_image_section_header)*
   Result.imageheader.FileHeader.NumberOfSections);
   Result.seccontentaddress:=(Result.secheaderaddress+
   sizeof(pe_image_section_header)*Result.imageheader.FileHeader.NumberOfSections+
   addralign-1) div addralign*addralign;
   {Make it ELF executable compatible}
   islower:=Result.seccontentaddress>elftextaddress;
   if(islower) then petextaddress:=Result.seccontentaddress else petextaddress:=elftextaddress;
   Result.seccontent:=conv_allocmem(sizeof(pe_content)*efiseccount);
   {Generate the PE section position}
   if(elfrodataaddress<>0) then
    begin
     perodataaddress:=petextaddress+elfrodataaddress-elftextaddress;
     pedataaddress:=perodataaddress+elfdataaddress-elfrodataaddress;
     perelocaddress:=pedataaddress+highaddress-elfdataaddress;
     pefiletextoffset:=Result.seccontentaddress;
     pefilerodataoffset:=pefiletextoffset+elffiletextend-elffiletextstart;
     pefiledataoffset:=pefilerodataoffset+elffilerodataend-elffilerodatastart;
     pefilerelocoffset:=pefiledataoffset+elffiledataend-elffiledatastart;
    end
   else
    begin
     perodataaddress:=0;
     pedataaddress:=petextaddress+elfdataaddress-elftextaddress;
     perelocaddress:=pedataaddress+highaddress-elfdataaddress;
     pefiletextoffset:=Result.seccontentaddress;
     pefiledataoffset:=pefiletextoffset+elffiletextend-elffiletextstart;
     pefilerelocoffset:=pefiledataoffset+elffiledataend-elffiledatastart;
    end;
   {Generate the Optional Header}
   if(islower) then Result.imageheader.OptionalHeader.AddressOfEntryPoint:=entrystart-elftextaddress+petextaddress
   else Result.imageheader.OptionalHeader.AddressOfEntryPoint:=entrystart;
   Result.imageheader.OptionalHeader.Magic:=pe_image_pe32plus_image_magic;
   Result.imageheader.OptionalHeader.MajorLinkerVersion:=0;
   Result.imageheader.OptionalHeader.MinorLinkerVersion:=0;
   Result.imageheader.OptionalHeader.MajorImageVersion:=0;
   Result.imageheader.OptionalHeader.MinorImageVersion:=0;
   Result.imageheader.OptionalHeader.MajorOperatingSystemVersion:=0;
   Result.imageheader.OptionalHeader.MinorOperatingSystemVersion:=0;
   Result.imageheader.OptionalHeader.MajorSubsystemVersion:=0;
   Result.imageheader.OptionalHeader.MinorSubsystemVersion:=0;
   Result.imageheader.OptionalHeader.Checksum:=0;
   Result.imageheader.OptionalHeader.ImageBase:=$00000000;
   Result.imageheader.OptionalHeader.BaseOfCode:=petextaddress;
   if(perodataaddress<>0) then Result.imageheader.OptionalHeader.BaseOfData:=perodataaddress
   else Result.imageheader.OptionalHeader.BaseOfData:=pedataaddress;
   Result.ImageHeader.OptionalHeader.SectionAlignment:=addralign;
   Result.imageheader.OptionalHeader.Subsystem:=apptype;
   Result.imageheader.OptionalHeader.Win32VersionValue:=0;
   Result.imageheader.OptionalHeader.SizeOfImage:=0;
   Result.imageheader.OptionalHeader.SizeOfHeaders:=
   (sizeof(pe_image_dos_header)+Result.dosstubsize+sizeof(dword)+
   sizeof(pe_image_file_header)+sizeof(pe_image_nt_header32)+
   sizeof(pe_image_section_header)*
   Result.imageheader.FileHeader.NumberOfSections+addralign-1) div addralign*addralign;
   Result.imageheader.OptionalHeader.DllCharacteristics:=0;
   Result.imageheader.OptionalHeader.NumberOfRvaandSizes:=16;
   if(elfrodataaddress<>0) then
    begin
     Result.imageheader.OptionalHeader.SizeOfCode:=elfrodataaddress-elftextaddress;
     Result.imageheader.OptionalHeader.SizeOfUninitializedData:=0;
     Result.imageheader.OptionalHeader.SizeOfInitializedData:=highaddress-elfrodataaddress;
    end
   else
    begin
     Result.imageheader.OptionalHeader.SizeOfCode:=elfdataaddress-elftextaddress;
     Result.imageheader.OptionalHeader.SizeOfUninitializedData:=0;
     Result.imageheader.OptionalHeader.SizeOfInitializedData:=highaddress-elfdataaddress;
    end;
   Result.imageheader.OptionalHeader.LoaderFlags:=0;
   Result.imageheader.OptionalHeader.SizeOfStackCommit:=0;
   Result.imageheader.OptionalHeader.SizeOfStackReserve:=0;
   Result.imageheader.OptionalHeader.SizeOfHeapCommit:=0;
   Result.imageheader.OptionalHeader.SizeOfHeapReserve:=0;
   {Generate the Section Content}
   if(haverodata) then
    begin
     i:=1;
     Ppe_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(elffiletextend-elffiletextstart);
     for j:=1 to textlist.seccount do
      begin
       tempaddress1:=SizeUint(Pelf_content(elf.seccontent+(textlist.secindex+j-1)^-1)^.ptr1);
       tempaddress2:=Pelf_section_header(elf.secheader+(textlist.secindex+j-1)^
       -1)^.sec32.section_header_address-elftextaddress+
       SizeUint(Ppe_content(Result.seccontent+i-1)^.ptr1);
       tempsize:=Pelf_section_header(elf.secheader+(textlist.secindex+j-1)^
       -1)^.sec32.section_header_size;
       conv_move(Pbyte(tempaddress1)^,Pbyte(tempaddress2)^,tempsize);
      end;
     inc(i);
     Ppe_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(elffilerodataend-elffilerodatastart);
     for j:=1 to rodatalist.seccount do
      begin
       tempaddress1:=SizeUint(Pelf_content(elf.seccontent+(rodatalist.secindex+j-1)^-1)^.ptr1);
       tempaddress2:=Pelf_section_header(elf.secheader+(rodatalist.secindex+j-1)^
       -1)^.sec32.section_header_address-elfrodataaddress+
       SizeUint(Ppe_content(Result.seccontent+i-1)^.ptr1);
       tempsize:=Pelf_section_header(elf.secheader+(rodatalist.secindex+j-1)^
       -1)^.sec32.section_header_size;
       conv_move(Pbyte(tempaddress1)^,Pbyte(tempaddress2)^,tempsize);
      end;
     inc(i);
     Ppe_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(elffiledataend-elffiledatastart);
     for j:=1 to datalist.seccount do
      begin
       tempaddress1:=SizeUint(Pelf_content(elf.seccontent+(datalist.secindex+j-1)^-1)^.ptr1);
       tempaddress2:=Pelf_section_header(elf.secheader+(datalist.secindex+j-1)^
       -1)^.sec32.section_header_address-elfdataaddress+
       SizeUint(Ppe_content(Result.seccontent+i-1)^.ptr1);
       tempsize:=Pelf_section_header(elf.secheader+(datalist.secindex+j-1)^
       -1)^.sec32.section_header_size;
       conv_move(Pbyte(tempaddress1)^,Pbyte(tempaddress2)^,tempsize);
      end;
    end
   else
    begin
     i:=1;
     Ppe_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(elffiletextend-elffiletextstart);
     for j:=1 to textlist.seccount do
      begin
       tempaddress1:=SizeUint(Pelf_content(elf.seccontent+(textlist.secindex+j-1)^-1)^.ptr1);
       tempaddress2:=Pelf_section_header(elf.secheader+(textlist.secindex+j-1)^
       -1)^.sec32.section_header_address-elftextaddress+
       SizeUint(Ppe_content(Result.seccontent+i-1)^.ptr1);
       tempsize:=Pelf_section_header(elf.secheader+(textlist.secindex+j-1)^
       -1)^.sec32.section_header_size;
       conv_move(Pbyte(tempaddress1)^,Pbyte(tempaddress2)^,tempsize);
      end;
     inc(i);
     Ppe_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(elffiledataend-elffiledatastart);
     for j:=1 to datalist.seccount do
      begin
       tempaddress1:=SizeUint(Pelf_content(elf.seccontent+(datalist.secindex+j-1)^-1)^.ptr1);
       tempaddress2:=Pelf_section_header(elf.secheader+(datalist.secindex+j-1)^
       -1)^.sec32.section_header_address-elfdataaddress+
       SizeUint(Ppe_content(Result.seccontent+i-1)^.ptr1);
       tempsize:=Pelf_section_header(elf.secheader+(datalist.secindex+j-1)^
       -1)^.sec32.section_header_size;
       conv_move(Pbyte(tempaddress1)^,Pbyte(tempaddress2)^,tempsize);
      end;
    end;
   {Generate the Base Relocation Table}
   breloclist.count:=0; breloclist.item:=nil; relocsize:=0; i:=1;
   while(i<=rela.list32.count)do
    begin
     j:=1; typeoffsetcount:=Pelf32_rela_item(rela.list32.item+i-1)^.count;
     while(j<=typeoffsetcount)do
      begin
       {Find the Relative Offset in PE file and write the add number}
       peRelaoffset:=conv_get_efi_relative_offset(elftextaddress,elfrodataaddress,elfdataaddress,
       pefiletextoffset,pefilerodataoffset,pefiledataoffset,
       Pelf32_rela(Pelf32_rela_item(rela.list32.item+i-1)^.rela+j-1)^.rela_offset);
       if(islower) then
        begin
         newoffset:=Pelf32_rela(Pelf32_rela_item(rela.list32.item+i-1)^.rela+j-1)^.rela_offset
         +Result.seccontentaddress-elftextaddress;
         newaddend:=Pelf32_rela(Pelf32_rela_item(rela.list32.item+i-1)^.rela+j-1)^.rela_addend
         +Result.seccontentaddress-elftextaddress;
        end
       else
        begin
         newoffset:=Pelf32_rela(Pelf32_rela_item(rela.list32.item+i-1)^.rela+j-1)^.rela_offset;
         newaddend:=Pelf32_rela(Pelf32_rela_item(rela.list32.item+i-1)^.rela+j-1)^.rela_addend;
        end;
       if(pefilerodataoffset<>0) then
        begin
         if(peRelaOffset.BaseAddr=pefiledataoffset) then
          begin
           writeoffset:=peRelaOffset.Offset;
           Pdword(Ppe_content(Result.seccontent+2)^.ptr1+writeoffset)^:=newaddend;
          end
         else if(peRelaOffset.BaseAddr=pefilerodataoffset) then
          begin
           writeoffset:=peRelaOffset.Offset;
           Pdword(Ppe_content(Result.seccontent+1)^.ptr1+writeoffset)^:=newaddend;
          end
         else
          begin
           writeoffset:=peRelaOffset.Offset;
           Pdword(Ppe_content(Result.seccontent)^.ptr1+writeoffset)^:=newaddend;
          end;
        end
       else
        begin
         if(peRelaOffset.BaseAddr=pefiledataoffset) then
          begin
           writeoffset:=peRelaOffset.Offset;
           Pdword(Ppe_content(Result.seccontent+1)^.ptr1+writeoffset)^:=newaddend;
          end
         else
          begin
           writeoffset:=peRelaOffset.Offset;
           Pdword(Ppe_content(Result.seccontent)^.ptr1+writeoffset)^:=newaddend;
          end;
        end;
       {If block exceeds limits,then create another block}
       if(j=1) or (newoffset-baseoffset>4095) then
        begin
         inc(breloclist.count); inc(relocsize,8);
         conv_reallocmem(breloclist.item,sizeof(pe_base_relocation_item)*breloclist.count);
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.VirtualAddress:=newoffset;
         baseoffset:=newoffset;
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.SizeOfBlock:=8;
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count:=0;
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc:=nil;
        end;
       inc(relocsize,2);
       inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.SizeOfBlock,2);
       inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count);
       conv_reallocmem(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc,j*2);
       Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
       Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.peType:=
       pe_image_rel_base_highlow;
       Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
       Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.Offset:=
       newoffset-baseoffset;
       inc(j);
      end;
     if(typeoffsetcount<2) or (typeoffsetcount-typeoffsetcount shr 1 shl 1<>0) then
      begin
       if(typeoffsetcount<2) then
       k:=2-typeoffsetcount
       else
       k:=2-(typeoffsetcount-typeoffsetcount shr 1 shl 1);
       while(k>0)do
        begin
         inc(relocsize,2);
         inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.SizeOfBlock,2);
         inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count);
         conv_reallocmem(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc,j*2);
         Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.peType:=
         pe_image_rel_base_absolute;
         Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.Offset:=0;
         dec(k); inc(j);
        end;
      end;
     inc(i);
    end;
   if(rela.list32.count=0) then
    begin
     inc(breloclist.count);
     conv_reallocmem(breloclist.item,sizeof(pe_base_relocation_item)*breloclist.count);
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.VirtualAddress:=
     elfdataaddress-elftextaddress+Result.seccontentaddress;
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.SizeOfBlock:=16;
     conv_reallocmem(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc,4);
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count:=0;
     inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count);
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.peType:=
     pe_image_rel_base_absolute;
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.Offset:=0;
     inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count);
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.peType:=
     pe_image_rel_base_absolute;
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.Offset:=0;
     relocsize:=12;
    end;
   {Free the Rela Section Content}
   i:=1;
   while(i<=rela.list32.count)do
    begin
     conv_freemem(Pelf32_rela_item(rela.list32.item+i-1)^.rela);
     inc(i);
    end;
   if(rela.list32.item<>nil) then conv_freemem(rela.list32.item);
   {Generate the Base Relocation Table in Memory}
   Ppe_content(Result.seccontent+efiseccount-1)^.ptr1:=conv_allocmem(relocsize); writeptr:=0;
   i:=1;
   while(i<=breloclist.count)do
    begin
     Ppe_image_base_relocation(Pointer(Ppe_content(Result.seccontent+efiseccount-1)^.ptr1)+writeptr)^:=
     Ppe_base_relocation_item(breloclist.item+i-1)^.base;
     inc(writeptr,8);
     j:=1;
     while(j<=Ppe_base_relocation_item(breloclist.item+i-1)^.count)do
      begin
       Ppe_image_type_offset(Pointer(Ppe_content(Result.seccontent+efiseccount-1)^.ptr1)+writeptr)^:=
       (Ppe_base_relocation_item(breloclist.item+i-1)^.reloc+j-1)^;
       inc(writeptr,2);
       inc(j);
      end;
     conv_freemem(Ppe_base_relocation_item(breloclist.item+i-1)^.reloc);
     Ppe_base_relocation_item(breloclist.item+i-1)^.count:=0;
     inc(i);
    end;
   if(breloclist.item<>nil) then conv_freemem(breloclist.item);
   {Generate the section header}
   i:=1;
   if(havetext=true) then
    begin
     Ppe_image_section_header(Result.secheader+i-1)^.Name:='.text';
     if(haverodata) then
     Ppe_image_section_header(Result.secheader+i-1)^.Misc.VirtualSize:=perodataaddress-petextaddress
     else Ppe_image_section_header(Result.secheader+i-1)^.Misc.VirtualSize:=pedataaddress-petextaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.NumberOfLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.SizeOfRawData:=elffiletextend-elffiletextstart;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRawData:=pefiletextoffset;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRelocation:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.VirtualAddress:=petextaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.Characteristics:=
     pe_image_scn_cnt_code or pe_image_mem_read or pe_image_mem_execute;
    end;
   if(haverodata=true) then
    begin
     inc(i);
     Ppe_image_section_header(Result.secheader+i-1)^.Name:='.rdata';
     Ppe_image_section_header(Result.secheader+i-1)^.Misc.VirtualSize:=pedataaddress-perodataaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.NumberOfLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.SizeOfRawData:=elffilerodataend-elffilerodatastart;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRawData:=pefilerodataoffset;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRelocation:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.VirtualAddress:=perodataaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.Characteristics:=
     pe_image_scn_cnt_initialized_data or pe_image_mem_read;
    end;
   if(havedata=true) then
    begin
     inc(i);
     Ppe_image_section_header(Result.secheader+i-1)^.Name:='.data';
     Ppe_image_section_header(Result.secheader+i-1)^.Misc.VirtualSize:=perelocaddress-pedataaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.NumberOfLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.SizeOfRawData:=elffiledataend-elffiledatastart;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRawData:=pefiledataoffset;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRelocation:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.VirtualAddress:=pedataaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.Characteristics:=
     pe_image_scn_cnt_initialized_data or pe_image_mem_read or pe_image_mem_write;
    end;
   inc(i);
   Ppe_image_section_header(Result.secheader+i-1)^.Name:='.reloc';
   Ppe_image_section_header(Result.secheader+i-1)^.Misc.VirtualSize:=relocsize;
   Ppe_image_section_header(Result.secheader+i-1)^.NumberOfLineNumbers:=0;
   Ppe_image_section_header(Result.secheader+i-1)^.PointerToLineNumbers:=0;
   Ppe_image_section_header(Result.secheader+i-1)^.SizeOfRawData:=relocsize;
   Ppe_image_section_header(Result.secheader+i-1)^.PointerToRawData:=pefilerelocoffset;
   Ppe_image_section_header(Result.secheader+i-1)^.PointerToRelocation:=0;
   Ppe_image_section_header(Result.secheader+i-1)^.VirtualAddress:=perelocaddress;
   Ppe_image_section_header(Result.secheader+i-1)^.Characteristics:=
   pe_image_scn_cnt_initialized_data or pe_image_mem_read or pe_image_mem_discardable;
   Result.imageheader.OptionalHeader.DataDirectory[6].virtualaddress:=perelocaddress;
   Result.ImageHeader.OptionalHeader.DataDirectory[6].Size:=relocsize;
   Result.imageheader.OptionalHeader.FileAlignment:=addralign;
   pefileSize:=(pefilerelocoffset+relocsize+addralign-1) div addralign*addralign;
   Result.imageheader.OptionalHeader.SizeOfImage:=
   (perelocaddress+relocsize+addralign-1) div addralign*addralign;
   Result.ImageHeader.OptionalHeader.Checksum:=0;
   efibuf:=conv_efi_to_buffer(Result,peFileSize);
   Result.peSize:=pefileSize;
   Result.ImageHeader.OptionalHeader.Checksum:=conv_generate_crc32(efibuf,pefileSize,0);
   conv_freemem(efibuf);
  end
 else if(elf.bit=64) then
  begin
   rela.list64.count:=0; rela.list64.item:=nil;
   entrystart:=elf.header.head64.elf64_entry;
   i:=2;
   while(i<=elf.header.head64.elf64_section_header_number)do
    begin
     if(Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_flags=
     elf_section_header_flag_exec_instr or elf_section_header_flag_alloc) and (havetext=false) then
      begin
       elftextaddress:=Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_address;
       elffiletextstart:=elftextaddress;
       havetext:=true;
      end
     else if(Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_flags=
     elf_section_header_flag_alloc) and (havetext) and (haverodata=false) then
      begin
       elfrodataaddress:=Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_address;
       elffilerodatastart:=elfrodataaddress;
       haverodata:=true;
      end
     else if(Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_flags=
     elf_section_header_flag_alloc or elf_section_header_flag_write)
     and (havetext) and (havedata=false) then
      begin
       elfdataaddress:=Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_address;
       elffiledatastart:=elfdataaddress;
       havedata:=true;
      end;
     if(Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_flags=
     elf_section_header_flag_exec_instr or elf_section_header_flag_alloc) and (havetext)
     and (haverodata=false) and (havedata=false) then
      begin
       inc(textlist.seccount);
       conv_reallocmem(textlist.secindex,textlist.seccount*2);
       elffiletextend:=Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_address
       +Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_size;
       (textlist.secindex+textlist.seccount-1)^:=i;
      end
     else if(Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_flags=
     elf_section_header_flag_alloc) and (havetext) and (haverodata) then
      begin
       inc(rodatalist.seccount);
       conv_reallocmem(rodatalist.secindex,rodatalist.seccount*2);
       elffilerodataend:=Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_address
       +Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_size;
       (rodatalist.secindex+rodatalist.seccount-1)^:=i;
      end
     else if(Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_flags=
     elf_section_header_flag_write or elf_section_header_flag_alloc) and (havetext)
     and (havedata) then
      begin
       inc(datalist.seccount);
       conv_reallocmem(datalist.secindex,datalist.seccount*2);
       elffiledataend:=Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_address
       +Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_size;
       (datalist.secindex+datalist.seccount-1)^:=i;
      end;
     if(Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_address
     +Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_size>highaddress)
     and(Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_flags and
     elf_section_header_flag_alloc=elf_section_header_flag_alloc) and (havetext) then
     highaddress:=Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_address
     +Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_size;
     if(Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_flags and
     elf_section_header_flag_alloc=elf_section_header_flag_alloc) and
     (Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_address_align>addralign) then
      begin
       addralign:=Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_address_align;
      end;
     if(Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_type=elf_section_header_rela) then
      begin
       inc(rela.list64.count); conv_reallocmem(rela.list64.item,rela.list64.count*sizeof(elf64_rela_item));
       Pelf64_rela_item(rela.list64.item+rela.list64.count-1)^.rela:=
       conv_allocmem(Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_size);
       Pelf64_rela_item(rela.list64.item+rela.list64.count-1)^.count:=
       Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_size div
       Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_entry_size;
       conv_move(Pelf_content(elf.seccontent+i-1)^.ptr1^,
       Pelf64_rela_item(rela.list64.item+rela.list64.count-1)^.rela^,
       Pelf_section_header(elf.secheader+i-1)^.sec64.section_header_size);
      end;
     inc(i);
    end;
   Result.imageheader.FileHeader.NumberOfSections:=Byte(havetext)+Byte(haverodata)+Byte(havedata)+1;
   efiseccount:=Result.imageheader.FileHeader.NumberOfSections;
   Result.imageheader.FileHeader.NumberOfSymbols:=0;
   Result.imageheader.FileHeader.PointerToSymbolTable:=0;
   Result.imageheader.FileHeader.SizeOfOptionalHeader:=sizeof(pe_image_nt_header64);
   Result.imageheader.FileHeader.Characteristics:=
   pe_image_file_executable_image or pe_image_file_line_nums_stripped
   or pe_image_file_local_syms_stripped or pe_image_file_debug_stripped or pe_image_file_large_address_aware;
   Result.imageheader.FileHeader.TimeDateStamp:=conv_generate_timestamp;
   if(elf.header.head64.elf64_machine=elf_machine_x86_64) then
    begin
     Result.imageheader.FileHeader.Machine:=pe_image_file_machine_amd64;
    end
   else if(elf.header.head64.elf64_machine=elf_machine_aarch64) then
    begin
     Result.imageheader.FileHeader.Machine:=pe_image_file_machine_arm64;
    end
   else if(elf.header.head64.elf64_machine=elf_machine_riscv) then
    begin
     Result.imageheader.FileHeader.Machine:=pe_image_file_machine_riscv64;
    end
   else if(elf.header.head64.elf64_machine=elf_machine_loongarch) then
    begin
     Result.imageheader.FileHeader.Machine:=pe_image_file_machine_loongarch64;
    end;
   Result.secheaderaddress:=sizeof(pe_image_dos_header)+Result.dosstubsize+sizeof(dword)+
   sizeof(pe_image_file_header)+sizeof(pe_image_nt_header64);
   Result.secheader:=conv_allocmem(sizeof(pe_image_section_header)*
   Result.imageheader.FileHeader.NumberOfSections);
   Result.seccontentaddress:=(Result.secheaderaddress+
   sizeof(pe_image_section_header)*Result.imageheader.FileHeader.NumberOfSections+
   addralign-1) div addralign*addralign;
   {Make it ELF executable compatible}
   islower:=Result.seccontentaddress>elftextaddress;
   if(islower) then petextaddress:=Result.seccontentaddress else petextaddress:=elftextaddress;
   Result.seccontent:=conv_allocmem(sizeof(pe_content)*efiseccount);
   {Generate the PE section position}
   if(elfrodataaddress<>0) then
    begin
     perodataaddress:=petextaddress+elfrodataaddress-elftextaddress;
     pedataaddress:=perodataaddress+elfdataaddress-elfrodataaddress;
     perelocaddress:=pedataaddress+highaddress-elfdataaddress;
     pefiletextoffset:=Result.seccontentaddress;
     pefilerodataoffset:=pefiletextoffset+elffiletextend-elffiletextstart;
     pefiledataoffset:=pefilerodataoffset+elffilerodataend-elffilerodatastart;
     pefilerelocoffset:=pefiledataoffset+elffiledataend-elffiledatastart;
    end
   else
    begin
     perodataaddress:=0;
     pedataaddress:=petextaddress+elfdataaddress-elftextaddress;
     perelocaddress:=pedataaddress+highaddress-elfdataaddress;
     pefiletextoffset:=Result.seccontentaddress;
     pefiledataoffset:=pefiletextoffset+elffiletextend-elffiletextstart;
     pefilerelocoffset:=pefiledataoffset+elffiledataend-elffiledatastart;
    end;
   {Generate the Optional Header}
   if(islower) then Result.imageheader.OptionalHeader64.AddressOfEntryPoint:=entrystart-elftextaddress+petextaddress
   else Result.imageheader.OptionalHeader64.AddressOfEntryPoint:=entrystart;
   Result.imageheader.OptionalHeader64.Magic:=pe_image_pe32plus_image_magic;
   Result.imageheader.OptionalHeader64.MajorLinkerVersion:=0;
   Result.imageheader.OptionalHeader64.MinorLinkerVersion:=0;
   Result.imageheader.OptionalHeader64.MajorImageVersion:=0;
   Result.imageheader.OptionalHeader64.MinorImageVersion:=0;
   Result.imageheader.OptionalHeader64.MajorOperatingSystemVersion:=0;
   Result.imageheader.OptionalHeader64.MinorOperatingSystemVersion:=0;
   Result.imageheader.OptionalHeader64.MajorSubsystemVersion:=0;
   Result.imageheader.OptionalHeader64.MinorSubsystemVersion:=0;
   Result.imageheader.OptionalHeader64.Checksum:=0;
   Result.imageheader.OptionalHeader64.ImageBase:=$00000000;
   Result.imageheader.OptionalHeader64.BaseOfCode:=petextaddress;
   Result.ImageHeader.OptionalHeader64.SectionAlignment:=addralign;
   Result.imageheader.OptionalHeader64.Subsystem:=apptype;
   Result.imageheader.OptionalHeader64.Win32VersionValue:=0;
   Result.imageheader.OptionalHeader64.SizeOfImage:=0;
   Result.imageheader.OptionalHeader64.SizeOfHeaders:=
   (sizeof(pe_image_dos_header)+Result.dosstubsize+sizeof(dword)+
   sizeof(pe_image_file_header)+sizeof(pe_image_nt_header64)+
   sizeof(pe_image_section_header)*
   Result.imageheader.FileHeader.NumberOfSections+addralign-1) div addralign*addralign;
   Result.imageheader.OptionalHeader64.DllCharacteristics:=0;
   Result.imageheader.OptionalHeader64.NumberOfRvaandSizes:=16;
   if(elfrodataaddress<>0) then
    begin
     Result.imageheader.OptionalHeader64.SizeOfCode:=elfrodataaddress-elftextaddress;
     Result.imageheader.OptionalHeader64.SizeOfUninitializedData:=0;
     Result.imageheader.OptionalHeader64.SizeOfInitializedData:=highaddress-elfrodataaddress;
    end
   else
    begin
     Result.imageheader.OptionalHeader64.SizeOfCode:=elfdataaddress-elftextaddress;
     Result.imageheader.OptionalHeader64.SizeOfUninitializedData:=0;
     Result.imageheader.OptionalHeader64.SizeOfInitializedData:=highaddress-elfdataaddress;
    end;
   Result.imageheader.OptionalHeader64.LoaderFlags:=0;
   Result.imageheader.OptionalHeader64.SizeOfStackCommit:=0;
   Result.imageheader.OptionalHeader64.SizeOfStackReserve:=0;
   Result.imageheader.OptionalHeader64.SizeOfHeapCommit:=0;
   Result.imageheader.OptionalHeader64.SizeOfHeapReserve:=0;
   {Generate the Section Content}
   if(haverodata) then
    begin
     i:=1;
     Ppe_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(elffiletextend-elffiletextstart);
     for j:=1 to textlist.seccount do
      begin
       tempaddress1:=SizeUint(Pelf_content(elf.seccontent+(textlist.secindex+j-1)^-1)^.ptr1);
       tempaddress2:=Pelf_section_header(elf.secheader+(textlist.secindex+j-1)^
       -1)^.sec64.section_header_address-elftextaddress+
       SizeUint(Ppe_content(Result.seccontent+i-1)^.ptr1);
       tempsize:=Pelf_section_header(elf.secheader+(textlist.secindex+j-1)^
       -1)^.sec64.section_header_size;
       conv_move(Pbyte(tempaddress1)^,Pbyte(tempaddress2)^,tempsize);
      end;
     inc(i);
     Ppe_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(elffilerodataend-elffilerodatastart);
     for j:=1 to rodatalist.seccount do
      begin
       tempaddress1:=SizeUint(Pelf_content(elf.seccontent+(rodatalist.secindex+j-1)^-1)^.ptr1);
       tempaddress2:=Pelf_section_header(elf.secheader+(rodatalist.secindex+j-1)^
       -1)^.sec64.section_header_address-elfrodataaddress+
       SizeUint(Ppe_content(Result.seccontent+i-1)^.ptr1);
       tempsize:=Pelf_section_header(elf.secheader+(rodatalist.secindex+j-1)^
       -1)^.sec64.section_header_size;
       conv_move(Pbyte(tempaddress1)^,Pbyte(tempaddress2)^,tempsize);
      end;
     inc(i);
     Ppe_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(elffiledataend-elffiledatastart);
     for j:=1 to datalist.seccount do
      begin
       tempaddress1:=SizeUint(Pelf_content(elf.seccontent+(datalist.secindex+j-1)^-1)^.ptr1);
       tempaddress2:=Pelf_section_header(elf.secheader+(datalist.secindex+j-1)^
       -1)^.sec64.section_header_address-elfdataaddress+
       SizeUint(Ppe_content(Result.seccontent+i-1)^.ptr1);
       tempsize:=Pelf_section_header(elf.secheader+(datalist.secindex+j-1)^
       -1)^.sec64.section_header_size;
       conv_move(Pbyte(tempaddress1)^,Pbyte(tempaddress2)^,tempsize);
      end;
    end
   else
    begin
     i:=1;
     Ppe_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(elffiletextend-elffiletextstart);
     for j:=1 to textlist.seccount do
      begin
       tempaddress1:=SizeUint(Pelf_content(elf.seccontent+(textlist.secindex+j-1)^-1)^.ptr1);
       tempaddress2:=Pelf_section_header(elf.secheader+(textlist.secindex+j-1)^
       -1)^.sec64.section_header_address-elftextaddress+
       SizeUint(Ppe_content(Result.seccontent+i-1)^.ptr1);
       tempsize:=Pelf_section_header(elf.secheader+(textlist.secindex+j-1)^
       -1)^.sec64.section_header_size;
       conv_move(Pbyte(tempaddress1)^,Pbyte(tempaddress2)^,tempsize);
      end;
     inc(i);
     Ppe_content(Result.seccontent+i-1)^.ptr1:=conv_allocmem(elffiledataend-elffiledatastart);
     for j:=1 to datalist.seccount do
      begin
       tempaddress1:=SizeUint(Pelf_content(elf.seccontent+(datalist.secindex+j-1)^-1)^.ptr1);
       tempaddress2:=Pelf_section_header(elf.secheader+(datalist.secindex+j-1)^
       -1)^.sec64.section_header_address-elfdataaddress+
       SizeUint(Ppe_content(Result.seccontent+i-1)^.ptr1);
       tempsize:=Pelf_section_header(elf.secheader+(datalist.secindex+j-1)^
       -1)^.sec64.section_header_size;
       conv_move(Pbyte(tempaddress1)^,Pbyte(tempaddress2)^,tempsize);
      end;
    end;
   {Generate the Base Relocation Table}
   breloclist.count:=0; breloclist.item:=nil; relocsize:=0; i:=1;
   while(i<=rela.list64.count)do
    begin
     j:=1; typeoffsetcount:=Pelf64_rela_item(rela.list64.item+i-1)^.count;
     while(j<=typeoffsetcount)do
      begin
       {Find the Relative Offset in PE file and write the add number}
       peRelaoffset:=conv_get_efi_relative_offset(elftextaddress,elfrodataaddress,elfdataaddress,
       pefiletextoffset,pefilerodataoffset,pefiledataoffset,
       Pelf64_rela(Pelf64_rela_item(rela.list64.item+i-1)^.rela+j-1)^.rela_offset);
       if(islower) then
        begin
         newoffset:=Pelf64_rela(Pelf64_rela_item(rela.list64.item+i-1)^.rela+j-1)^.rela_offset
         +Result.seccontentaddress-elftextaddress;
         newaddend:=Pelf64_rela(Pelf64_rela_item(rela.list64.item+i-1)^.rela+j-1)^.rela_addend
         +Result.seccontentaddress-elftextaddress;
        end
       else
        begin
         newoffset:=Pelf64_rela(Pelf64_rela_item(rela.list64.item+i-1)^.rela+j-1)^.rela_offset;
         newaddend:=Pelf64_rela(Pelf64_rela_item(rela.list64.item+i-1)^.rela+j-1)^.rela_addend;
        end;
       if(pefilerodataoffset<>0) then
        begin
         if(peRelaOffset.BaseAddr=pefiledataoffset) then
          begin
           writeoffset:=PeRelaOffset.offset;
           Pqword(Ppe_content(Result.seccontent+2)^.ptr1+writeoffset)^:=newaddend;
          end
         else if(peRelaOffset.BaseAddr=pefilerodataoffset) then
          begin
           writeoffset:=PeRelaOffset.offset;
           Pqword(Ppe_content(Result.seccontent+1)^.ptr1+writeoffset)^:=newaddend;
          end
         else
          begin
           writeoffset:=PeRelaOffset.offset;
           Pqword(Ppe_content(Result.seccontent)^.ptr1+writeoffset)^:=newaddend;
          end;
        end
       else
        begin
         if(peRelaOffset.BaseAddr=pefiledataoffset) then
          begin
           writeoffset:=PeRelaOffset.offset;
           Pqword(Ppe_content(Result.seccontent+1)^.ptr1+writeoffset)^:=newaddend;
          end
         else
          begin
           writeoffset:=PeRelaOffset.offset;
           Pqword(Ppe_content(Result.seccontent)^.ptr1+writeoffset)^:=newaddend;
          end;
        end;
       {If block exceeds limits,then create another block}
       if(j=1) or (newoffset-baseoffset>4095) then
        begin
         inc(breloclist.count); inc(relocsize,8);
         conv_reallocmem(breloclist.item,sizeof(pe_base_relocation_item)*breloclist.count);
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.VirtualAddress:=newoffset;
         baseoffset:=newoffset;
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.SizeOfBlock:=8;
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count:=0;
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc:=nil;
        end;
       inc(relocsize,2);
       inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.SizeOfBlock,2);
       inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count);
       conv_reallocmem(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc,j*2);
       Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
       Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.peType:=
       pe_image_rel_base_dir64;
       Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
       Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.Offset:=
       newoffset-baseoffset;
       inc(j);
      end;
     if(typeoffsetcount<4) or (typeoffsetcount-typeoffsetcount shr 2 shl 2<>0) then
      begin
       if(typeoffsetcount<4) then
       k:=4-typeoffsetcount
       else
       k:=4-(typeoffsetcount-typeoffsetcount shr 2 shl 2);
       while(k>0)do
        begin
         inc(relocsize,2);
         inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.SizeOfBlock,2);
         inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count);
         conv_reallocmem(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc,j*2);
         Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.peType:=
         pe_image_rel_base_absolute;
         Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
         Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.Offset:=0;
         dec(k); inc(j);
        end;
      end;
     inc(i);
    end;
   if(rela.list64.count=0) then
    begin
     inc(breloclist.count);
     conv_reallocmem(breloclist.item,sizeof(pe_base_relocation_item)*breloclist.count);
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.VirtualAddress:=
     elfdataaddress-elftextaddress+Result.seccontentaddress;
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.base.SizeOfBlock:=16;
     conv_reallocmem(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc,4);
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count:=0;
     inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count);
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.peType:=
     pe_image_rel_base_absolute;
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.Offset:=0;
     inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count);
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.peType:=
     pe_image_rel_base_absolute;
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.Offset:=0;
     inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count);
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.peType:=
     pe_image_rel_base_absolute;
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.Offset:=0;
     inc(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count);
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.peType:=
     pe_image_rel_base_absolute;
     Ppe_image_type_offset(Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.reloc+
     Ppe_base_relocation_item(breloclist.item+breloclist.count-1)^.count-1)^.Offset:=0;
     relocsize:=16;
    end;
   {Free the Rela Section Content}
   i:=1;
   while(i<=rela.list64.count)do
    begin
     conv_freemem(Pelf64_rela_item(rela.list64.item+i-1)^.rela);
     inc(i);
    end;
   if(rela.list64.item<>nil) then conv_freemem(rela.list64.item);
   {Generate the Base Relocation Table in Memory}
   Ppe_content(Result.seccontent+efiseccount-1)^.ptr1:=conv_allocmem(relocsize); writeptr:=0;
   i:=1;
   while(i<=breloclist.count)do
    begin
     Ppe_image_base_relocation(Pointer(Ppe_content(Result.seccontent+efiseccount-1)^.ptr1)+writeptr)^:=
     Ppe_base_relocation_item(breloclist.item+i-1)^.base;
     inc(writeptr,8);
     j:=1;
     while(j<=Ppe_base_relocation_item(breloclist.item+i-1)^.count)do
      begin
       Ppe_image_type_offset(Pointer(Ppe_content(Result.seccontent+efiseccount-1)^.ptr1)+writeptr)^:=
       (Ppe_base_relocation_item(breloclist.item+i-1)^.reloc+j-1)^;
       inc(writeptr,2);
       inc(j);
      end;
     conv_freemem(Ppe_base_relocation_item(breloclist.item+i-1)^.reloc);
     Ppe_base_relocation_item(breloclist.item+i-1)^.count:=0;
     inc(i);
    end;
   if(breloclist.item<>nil) then conv_freemem(breloclist.item);
   {Generate the section header}
   i:=1;
   if(havetext=true) then
    begin
     Ppe_image_section_header(Result.secheader+i-1)^.Name:='.text';
     if(haverodata) then
     Ppe_image_section_header(Result.secheader+i-1)^.Misc.VirtualSize:=perodataaddress-petextaddress
     else Ppe_image_section_header(Result.secheader+i-1)^.Misc.VirtualSize:=pedataaddress-petextaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.NumberOfLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.SizeOfRawData:=elffiletextend-elffiletextstart;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRawData:=pefiletextoffset;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRelocation:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.VirtualAddress:=petextaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.Characteristics:=
     pe_image_scn_cnt_code or pe_image_mem_read or pe_image_mem_execute;
    end;
   if(haverodata=true) then
    begin
     inc(i);
     Ppe_image_section_header(Result.secheader+i-1)^.Name:='.rdata';
     Ppe_image_section_header(Result.secheader+i-1)^.Misc.VirtualSize:=pedataaddress-perodataaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.NumberOfLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.SizeOfRawData:=elffilerodataend-elffilerodatastart;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRawData:=pefilerodataoffset;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRelocation:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.VirtualAddress:=perodataaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.Characteristics:=
     pe_image_scn_cnt_initialized_data or pe_image_mem_read;
    end;
   if(havedata=true) then
    begin
     inc(i);
     Ppe_image_section_header(Result.secheader+i-1)^.Name:='.data';
     Ppe_image_section_header(Result.secheader+i-1)^.Misc.VirtualSize:=perelocaddress-pedataaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.NumberOfLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToLineNumbers:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.SizeOfRawData:=elffiledataend-elffiledatastart;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRawData:=pefiledataoffset;
     Ppe_image_section_header(Result.secheader+i-1)^.PointerToRelocation:=0;
     Ppe_image_section_header(Result.secheader+i-1)^.VirtualAddress:=pedataaddress;
     Ppe_image_section_header(Result.secheader+i-1)^.Characteristics:=
     pe_image_scn_cnt_initialized_data or pe_image_mem_read or pe_image_mem_write;
    end;
   inc(i);
   Ppe_image_section_header(Result.secheader+i-1)^.Name:='.reloc';
   Ppe_image_section_header(Result.secheader+i-1)^.Misc.VirtualSize:=relocsize;
   Ppe_image_section_header(Result.secheader+i-1)^.NumberOfLineNumbers:=0;
   Ppe_image_section_header(Result.secheader+i-1)^.PointerToLineNumbers:=0;
   Ppe_image_section_header(Result.secheader+i-1)^.SizeOfRawData:=relocsize;
   Ppe_image_section_header(Result.secheader+i-1)^.PointerToRawData:=pefilerelocoffset;
   Ppe_image_section_header(Result.secheader+i-1)^.PointerToRelocation:=0;
   Ppe_image_section_header(Result.secheader+i-1)^.VirtualAddress:=perelocaddress;
   Ppe_image_section_header(Result.secheader+i-1)^.Characteristics:=
   pe_image_scn_cnt_initialized_data or pe_image_mem_read or pe_image_mem_discardable;
   Result.imageheader.OptionalHeader64.DataDirectory[6].virtualaddress:=perelocaddress;
   Result.ImageHeader.OptionalHeader64.DataDirectory[6].Size:=relocsize;
   Result.imageheader.OptionalHeader64.FileAlignment:=addralign;
   pefileSize:=(pefilerelocoffset+relocsize+addralign-1) div addralign*addralign;
   Result.peSize:=pefileSize;
   Result.imageheader.OptionalHeader64.SizeOfImage:=
   (perelocaddress+relocsize+addralign-1) div addralign*addralign;
   Result.ImageHeader.OptionalHeader64.Checksum:=0;
   efibuf:=conv_efi_to_buffer(Result,pefileSize);
   Result.ImageHeader.OptionalHeader64.Checksum:=conv_generate_crc32(efibuf,pefilesize,0);
   conv_freemem(efibuf);
  end;
end;
procedure conv_efi_write(efi:pe_file;fn:string);
var efibuf:Pbyte;
    i:SizeUint;
begin
 efibuf:=conv_efi_to_buffer(efi,efi.peSize);
 if(efi.bit=32) then
  begin
   for i:=1 to efi.peSize shr 2 do
    begin
     conv_io_write(fn,Pdword(efibuf+(i-1)*4)^,(i-1)*4,4);
    end;
  end
 else if(efi.bit=64) then
  begin
   for i:=1 to efi.PeSize shr 2 do
    begin
     conv_io_write(fn,Pdword(efibuf+(i-1)*4)^,(i-1)*4,4);
    end;
  end;
 conv_freemem(efibuf);
end;
procedure conv_elf_free(var elf:elf_file);
var i,total:SizeUint;
begin
 if(elf.bit=32) then total:=elf.header.head32.elf32_section_header_number
 else if(elf.bit=64) then total:=elf.header.head64.elf64_section_header_number;
 i:=1;
 while(i<=total)do
  begin
   if(Pelf_content(elf.seccontent+i-1)^.ptr1<>nil) then
   conv_freemem(Pelf_content(elf.seccontent+i-1)^.ptr1);
   inc(i);
  end;
 if(elf.seccontent<>nil) then conv_freemem(elf.seccontent);
 if(elf.secheader<>nil) then conv_freemem(elf.secheader);
 if(elf.proheader<>nil) then conv_freemem(elf.proheader);
end;
procedure conv_pe_free(var pe:pe_file);
var i:SizeUint;
begin
 conv_freemem(pe.dosstub);
 i:=1;
 while(i<=pe.imageheader.FileHeader.NumberOfSections)do
  begin
   conv_freemem((pe.seccontent+i-1)^.ptr1);
   inc(i);
  end;
 conv_freemem(pe.secheader); conv_freemem(pe.seccontent);
end;

end.
