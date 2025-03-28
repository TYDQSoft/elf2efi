unit convmem;

interface

{$MODE FPC}

type natuint=SizeUint;
     natint=SizeInt;
     heap_item=bitpacked record
               haveprev:boolean;
               allocated:0..63;
               havenext:boolean;
               end;
     Pheap_item=^heap_item;
     heap_record=packed record
                 mem_start:Pointer;
                 mem_end:Pointer;
                 mem_block_power:byte;
                 item_max_pos:natuint;
                 end;

var memheap:heap_record;

function heap_initialize(startpos,endpos:natuint;blockpower:byte):heap_record;
function tydq_getmem(size:natuint):Pointer;
procedure tydq_getmem(var ptr:Pointer;size:natuint);
function tydq_getmemsize(ptr:Pointer):natuint;
function tydq_allocmem(size:natuint):Pointer;
procedure tydq_freemem(var ptr:Pointer);
procedure tydq_move(const src;var dest;Size:natuint);
function tydq_reallocmem(var ptr:Pointer;size:natuint):Pointer;

implementation

function heap_initialize(startpos,endpos:natuint;blockpower:byte):heap_record;
var res:heap_record;
begin
 res.mem_start:=Pointer(startpos); res.mem_end:=Pointer(endpos);
 res.mem_block_power:=blockpower; res.item_max_pos:=0;
 heap_initialize:=res;
end;
function heap_get_total_size(heap:heap_record):natuint;
begin
 heap_get_total_size:=Natuint(heap.mem_end-heap.mem_start)+1;
end;
function heap_conv_addr_to_index(heap:heap_record;addr:Pointer;isitem:Boolean):natuint;
begin
 if(isitem) then heap_conv_addr_to_index:=(heap.mem_end-addr) shr heap.mem_block_power
 else heap_conv_addr_to_index:=(addr-heap.mem_start) shr heap.mem_block_power+1;
end;
function heap_conv_index_to_addr(heap:heap_record;index:natuint;isitem:boolean):Pointer;
begin
 if(isitem) then heap_conv_index_to_addr:=Pointer(heap.mem_end-index*sizeof(heap_item))
 else heap_conv_index_to_addr:=Pointer(heap.mem_start+(index-1) shl heap.mem_block_power);
end;
function heap_conv_index_to_item(heap:heap_record;index:natuint):heap_item;
begin
 heap_conv_index_to_item:=Pheap_item(heap.mem_end-index*sizeof(heap_item))^;
end;
function heap_conv_mem_to_item(heap:heap_record;mem:Pointer):heap_item;
var index:natuint;
    res:heap_item;
begin
 index:=Natuint(mem-heap.mem_start) shr heap.mem_block_power+1;
 heap_conv_mem_to_item:=Pheap_item(mem-index*sizeof(heap_item))^;
end;
function heap_get_mem_count(heap:heap_record;ptr:Pointer):natuint;
var i1,i2,index:natuint;
    tempitem:heap_item;
begin
 if(ptr=nil) or (ptr<heap.mem_start) or (ptr>heap.mem_end) then exit(0);
 index:=heap_conv_addr_to_index(heap,ptr,false);
 i1:=index; i2:=index;
 tempitem:=heap_conv_index_to_item(heap,i1);
 if(tempitem.havenext) and (tempitem.haveprev) then
  begin
   while(i1<heap.item_max_pos)do
    begin
     tempitem:=heap_conv_index_to_item(heap,i1);
     if(tempitem.havenext=false) then break;
     inc(i1);
    end;
   while(i2>1)do
    begin
     tempitem:=heap_conv_index_to_item(heap,i2);
     if(tempitem.haveprev=false) then break;
     dec(i2);
    end;
   heap_get_mem_count:=i1-i2+1;
  end
 else if(tempitem.havenext) then
  begin
   while(i1<heap.item_max_pos)do
    begin
     tempitem:=heap_conv_index_to_item(heap,i1);
     if(tempitem.havenext=false) then break;
     inc(i1);
    end;
   heap_get_mem_count:=(i1-index+1);
  end
 else if(tempitem.haveprev) then
  begin
   while(i2>1)do
    begin
     tempitem:=heap_conv_index_to_item(heap,i2);
     if(tempitem.haveprev=false) then break;
     dec(i2);
    end;
   heap_get_mem_count:=(index-i2+1);
  end
 else
  begin
   heap_get_mem_count:=1;
  end;
end;
function heap_get_mem_size(heap:heap_record;ptr:Pointer):natuint;
var i1,i2,index:natuint;
    tempitem:heap_item;
begin
 if(ptr=nil) or (ptr<heap.mem_start) or (ptr>heap.mem_end) then exit(0);
 index:=heap_conv_addr_to_index(heap,ptr,false);
 i1:=index; i2:=index;
 tempitem:=heap_conv_index_to_item(heap,i1);
 if(tempitem.havenext) and (tempitem.haveprev) then
  begin
   while(i1<heap.item_max_pos)do
    begin
     tempitem:=heap_conv_index_to_item(heap,i1);
     if(tempitem.havenext=false) then break;
     inc(i1);
    end;
   while(i2>1)do
    begin
     tempitem:=heap_conv_index_to_item(heap,i2);
     if(tempitem.haveprev=false) then break;
     dec(i2);
    end;
   heap_get_mem_size:=(i1-i2+1) shl heap.mem_block_power;
  end
 else if(tempitem.havenext) then
  begin
   while(i1<heap.item_max_pos)do
    begin
     tempitem:=heap_conv_index_to_item(heap,i1);
     if(tempitem.havenext=false) then break;
     inc(i1);
    end;
   heap_get_mem_size:=(i1-index+1) shl heap.mem_block_power;
  end
 else if(tempitem.haveprev) then
  begin
   while(i2>1)do
    begin
     tempitem:=heap_conv_index_to_item(heap,i2);
     if(tempitem.haveprev=false) then break;
     dec(i2);
    end;
   heap_get_mem_size:=(index-i2+1) shl heap.mem_block_power;
  end
 else
  begin
   heap_get_mem_size:=1 shl heap.mem_block_power;
  end;
end;
function heap_get_mem_start(heap:heap_record;ptr:Pointer):Pointer;
var i1,index:natuint;
    tempitem:heap_item;
begin
 if(ptr=nil) or (ptr<heap.mem_start) or (ptr>heap.mem_end) then exit(nil);
 index:=heap_conv_addr_to_index(heap,ptr,false);
 tempitem:=heap_conv_index_to_item(heap,index);
 i1:=index;
 if(tempitem.haveprev) then
  begin
   while(i1>0)do
    begin
     tempitem:=heap_conv_index_to_item(heap,i1);
     if(tempitem.haveprev=false) then break;
     dec(i1);
    end;
   heap_get_mem_start:=heap.mem_start+(i1-1) shl heap.mem_block_power;
  end
 else
  begin
   heap_get_mem_start:=heap.mem_start+(index-1) shl heap.mem_block_power;
  end;
end;
function heap_request_mem(var heap:heap_record;size:natuint;meminit:boolean):Pointer;
var blockcount:SizeUint;
    i1,i2,i3,i4:natuint;
    tempptr:Pheap_item;
    tempmemptr:Pqword;
    totalsize:natuint;
begin
 totalsize:=heap_get_total_size(heap);
 blockcount:=(size+1 shl heap.mem_block_power-1) shr heap.mem_block_power;
 if(blockcount=0) then heap_request_mem:=nil
 else
  begin
   {Search for empty block which is in heap.item_max_pos
    If it is suitable,allocate it in heap.item_max_pos
    else,raise the item_max_pos for allocating memory}
   if(heap.item_max_pos=0) and (blockcount shl heap.mem_block_power
   +blockcount<=totalsize) then
    begin
     i1:=1;
     while(i1<=blockcount)do
      begin
       tempptr:=heap_conv_index_to_addr(heap,i1,true);
       tempmemptr:=heap_conv_index_to_addr(heap,i1,false);
       if(i1>1) then tempptr^.haveprev:=true else tempptr^.haveprev:=false;
       tempptr^.allocated:=1;
       if(i1<blockcount) then tempptr^.havenext:=true else tempptr^.havenext:=false;
       if(meminit) then
        begin
         for i2:=1 to 1 shl heap.mem_block_power shr 3 do (tempmemptr+i2-1)^:=0;
        end;
       inc(i1);
      end;
     heap_request_mem:=heap.mem_start;
     inc(heap.item_max_pos,blockcount);
    end
   else if(heap.item_max_pos>0) then
    begin
     i1:=1; i2:=0;
     while(i1<=heap.item_max_pos)do
      begin
       tempptr:=heap_conv_index_to_addr(heap,i1,true);
       if(tempptr^.allocated=0) and (i2<blockcount) then inc(i2)
       else if(tempptr^.allocated=0) then break
       else i2:=0;
       inc(i1);
      end;
     if(i2=0) and ((heap.item_max_pos+blockcount)
     shl heap.mem_block_power+(heap.item_max_pos+blockcount)<=totalsize) then
      begin
       i1:=1;
       while(i1<=blockcount)do
        begin
         tempptr:=heap_conv_index_to_addr(heap,heap.item_max_pos+i1,true);
         tempmemptr:=heap_conv_index_to_addr(heap,heap.item_max_pos+i1,false);
         if(i1>1) then tempptr^.haveprev:=true else tempptr^.haveprev:=false;
         tempptr^.allocated:=1;
         if(i1<blockcount) then tempptr^.havenext:=true else tempptr^.havenext:=false;
         if(meminit) then
          begin
           for i4:=1 to 1 shl heap.mem_block_power shr 3 do (tempmemptr+i4-1)^:=0;
          end;
         inc(i1);
        end;
       heap_request_mem:=heap.mem_start+heap.item_max_pos shl heap.mem_block_power;
       inc(heap.item_max_pos,blockcount);
      end
     else if(i2=0) then
      begin
       heap_request_mem:=nil;
      end
     else
      begin
       i3:=i1-i2+1;
       while(i3<=i1)do
        begin
         tempptr:=heap_conv_index_to_addr(heap,i3,true);
         tempmemptr:=heap_conv_index_to_addr(heap,i3,false);
         if(i3>i1-i2+1) then tempptr^.haveprev:=true else tempptr^.haveprev:=false;
         tempptr^.allocated:=1;
         if(i3<i1) then tempptr^.havenext:=true else tempptr^.havenext:=false;
         if(meminit) then
          begin
           for i4:=1 to 1 shl heap.mem_block_power shr 3 do (tempmemptr+i4-1)^:=0;
          end;
         inc(i3);
        end;
       heap_request_mem:=heap.mem_start+(i1-i2) shl heap.mem_block_power;
      end;
    end
   else heap_request_mem:=nil;
  end;
end;
procedure heap_free_mem(var heap:heap_record;var ptr:Pointer;forcenil:boolean);
var start:Pointer;
    index,i,blockcount:natuint;
    tempptr:Pheap_item;
begin
 if(ptr=nil) then exit;
 start:=heap_get_mem_start(heap,ptr);
 index:=heap_conv_addr_to_index(heap,start,true);
 blockcount:=heap_get_mem_size(heap,ptr) shr heap.mem_block_power;
 i:=1;
 while(i<=blockcount)do
  begin
   tempptr:=heap_conv_index_to_addr(heap,index+i-1,true);
   if(tempptr^.allocated<>0) then tempptr^.allocated:=0;
   tempptr^.haveprev:=false; tempptr^.havenext:=false;
   inc(i);
  end;
 i:=heap.item_max_pos;
 while(i>0)do
  begin
   tempptr:=heap_conv_index_to_addr(heap,i-1,true);
   if(tempptr^.allocated<>0) then break;
   dec(i);
  end;
 heap.item_max_pos:=i;
 if(forcenil) then ptr:=nil;
end;
procedure heap_move_mem(heap:heap_record;src,dest:Pointer);
var start1,start2:Pqword;
    size1,size2,i:natuint;
begin
 if(src=nil) or (dest=nil) then exit;
 start1:=heap_get_mem_start(heap,src);
 start2:=heap_get_mem_start(heap,dest);
 size1:=heap_get_mem_size(heap,src);
 size2:=heap_get_mem_size(heap,dest);
 if(size1<>0) and (size2<>0) then
  begin
   if(size1>size2) then
    begin
     for i:=1 to size2 shr 3 do (start2+i-1)^:=(start1+i-1)^;
    end
   else if(size1<=size2) then
    begin
     for i:=1 to size1 shr 3 do (start2+i-1)^:=(start1+i-1)^;
    end;
  end;
end;
function tydq_getmem(size:natuint):Pointer;
begin
 tydq_getmem:=heap_request_mem(memheap,size,false);
end;
procedure tydq_getmem(var ptr:Pointer;size:natuint);
begin
 ptr:=heap_request_mem(memheap,size,false);
end;
function tydq_getmemsize(ptr:Pointer):natuint;
begin
 tydq_getmemsize:=heap_get_mem_size(memheap,ptr);
end;
function tydq_allocmem(size:natuint):Pointer;
begin
 tydq_allocmem:=heap_request_mem(memheap,size,true);
end;
procedure tydq_freemem(var ptr:Pointer);
begin
 heap_free_mem(memheap,ptr,true);
end;
procedure tydq_move(const src;var dest;Size:natuint);
var i:SizeUint;
    d1,d2:Pdword;
    w1,w2:Pword;
    b1,b2:Pbyte;
begin
 if(Size-Size shr 2 shl 2=0) then
  begin
   d1:=Pdword(@src); d2:=Pdword(@dest);
   for i:=1 to Size shr 2 do (d2+i-1)^:=(d1+i-1)^;
  end
 else if(Size-Size shr 1 shl 1=0) then
  begin
   w1:=Pword(@src); w2:=Pword(@dest);
   for i:=1 to Size shr 1 do (w2+i-1)^:=(w1+i-1)^;
  end
 else
  begin
   b1:=Pbyte(@src); b2:=Pbyte(@dest);
   for i:=1 to Size do (b2+i-1)^:=(b1+i-1)^;
  end;
end;
function tydq_reallocmem(var ptr:Pointer;size:natuint):Pointer;
var newptr,oldptr:Pointer;
begin
 newptr:=heap_request_mem(memheap,size,true);
 oldptr:=ptr;
 heap_move_mem(memheap,oldptr,newptr);
 heap_free_mem(memheap,oldptr,false);
 ptr:=newptr;
 tydq_reallocmem:=newptr;
end;

end.

