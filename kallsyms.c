#include "bootunpack.h"
#include "stdio.h"
#include "math.h"
#ifdef _WIN32
#include "windows.h"
#else
#endif
/*
#include "../include/capstone.h"
#include "../include/arm.h"

int disasm(krninfo* krn)
{
    csh handle;
	cs_insn *insn;
	size_t count;


	if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK)
		return -1;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, krn->vmlinuzbuffer, krn->vmlinuz_size, krn->kernel_base, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++)
		{
			printf("0x%I64x:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,	insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
}*/

//some you want hardcode kernel address
extern int g_save_ioctl_func;
unsigned int sys_call_table_addr = 0;
FILE* fdevice_log = 0;

static const char* used_symbol[] =
{
	"sys_call_table",
    "ptmx_fops",
	"prepare_kernel_cred",
	"commit_creds",
	"delayed_rsp_id",
	"dev_attr_ro",
	"sys_oabi_semop",
	"perf_swevent_enabled",
	"sys_setresuid",
	"sys_setresgid",
	"blk_set_ro_secure_debuggable",
	"sony_ric_enabled"
};

static unsigned int kernel_base[]=
{
	0xc0008000,
	0x80008000,
	0xc0008180,//coolpad
	0xc00081c0,//xiaomi
};

size_t _strncpy_(char* dst,const char* src,size_t max)
{
	int n = 0;
	if(dst == 0 || src ==0 || max ==0 )
		return n;

	while(*dst++ = *src++)
		n++;

	return n;
}

unsigned int* get_kallsyms_addresses(krninfo* krn)
{
	int num = 0;
	int offset =0;
	int stext;
	unsigned int kallsyms_addresses_offset = 0;
	unsigned int addr;
    unsigned char * pdata =  krn->vmlinuzbuffer;
	unsigned int highmark = krn->kernel_base>>24;
	unsigned int next_addr = 0;

	while(krn && kallsyms_addresses_offset < krn->vmlinuz_size-4)
    {
		addr = *(unsigned int*)(pdata+kallsyms_addresses_offset);
		num = 0;

		while(addr >= krn->kernel_base && ((addr >> 24)== highmark) && addr < krn->kernel_base+krn->vmlinuz_size)
		{
			if (addr == 0 || num > 0x4000)
			{
				stext = *(unsigned int*)(pdata+kallsyms_addresses_offset);
				if(stext == krn->kernel_base )
				{
					printf("kernel base %.8x\n",krn->kernel_base);
					printf("going on,kall_sym_address offset %x addr %x \n",kallsyms_addresses_offset,kallsyms_addresses_offset+krn->kernel_base);
					krn->kallsyms_addresses = kallsyms_addresses_offset;
				    return krn->kallsyms_addresses;
				}
				else
				{
                    next_addr = *(unsigned int*)(pdata+kallsyms_addresses_offset+4);
					if(next_addr == stext && stext >= 0xc0008000)
						krn->kernel_base = stext;
				}	
			}
			num++;
			offset +=4;
            addr = *(unsigned int*)(pdata+offset);
		}

		kallsyms_addresses_offset+=4;
		offset = kallsyms_addresses_offset;
    }

	return 0;
}

int get_kallsyms_nums(krninfo* krn)
{
	int num = 0;
	unsigned int addr = 0;
	unsigned char * pdata =  krn->vmlinuzbuffer;
	unsigned int highmark = krn->kernel_base>>24;
	unsigned int offset = krn->kallsyms_addresses;

	if(krn && krn->kallsyms_addresses)
	{
		addr = *(unsigned int*)(pdata+offset);
		num = 0;

		while(addr >= krn->kernel_base && ((addr >> 24)== highmark|| (addr >> 24)== highmark+1) && offset < krn->vmlinuz_size -4)
		{
			if (addr == 0 )
			{
				break;
			}
			num++;
			offset +=4;
			addr = *(unsigned int*)(pdata+offset);
		}
	}

	//max 4 dwords
	if(abs(addr-num)<=0x20)
	{
		num=addr;
		printf("good,get kall_sym_nums 0x%x offset 0x%x \n",num,offset);
	}
	else
	{
		offset +=4;
		addr = *(unsigned int*)(pdata+offset);
		if(abs(addr-num)<=0x20)
		{
			num=addr;
			printf("good,get kall_sym_nums 0x%x offset 0x%x \n",num,offset);
		}
		else
		{
			offset +=4;
			addr = *(unsigned int*)(pdata+offset);
			if(abs(addr-num)<=0x20)
			{
				num=addr;
				printf("good,get kall_sym_nums 0x%x offset 0x%x \n",num,offset);
			}
			else
			{
				offset +=4;
				addr = *(unsigned int*)(pdata+offset);
				if(abs(addr-num)<=0x20)
				{
					num=addr;
					printf("good,get kall_sym_nums 0x%x offset 0x%x \n",num,offset);
				}
			}
		}
	}

	krn->kallsyms_num_syms_offs = offset+4;

	return krn->kallsyms_num_syms = num;
}

unsigned char* get_kallsyms_markers(krninfo* krn)
{
	int i ;
	unsigned char * pdata;

   if(krn && krn->kallsyms_num_syms_offs)
   {
	   krn->kallsyms_names = KERNEL_VARIBLE_ALIGN(krn->kallsyms_num_syms_offs+4);
	   pdata =  krn->vmlinuzbuffer+(int)krn->kallsyms_names;

	   i =0;
	   krn->kallsyms_markers = krn->kallsyms_names;
       while(*pdata && pdata < krn->vmlinuzbuffer+krn->vmlinuz_size-1)// && *pdata <= 0x58)
	   {
#ifndef __GNUC__
		  (unsigned char*)krn->kallsyms_markers+=*pdata+1;
#else
          krn->kallsyms_markers= (unsigned char*)krn->kallsyms_markers+*pdata+1;
#endif
		  pdata+=*pdata+1;
		  i++;
	   }

	   if(i == krn->kallsyms_num_syms)
	   {
		   krn->kallsyms_markers = KERNEL_VARIBLE_ALIGN(krn->kallsyms_markers);
		   printf("great,found kallsyms_markers offset 0x%x addr 0x%x \n",krn->kallsyms_markers,krn->kernel_base+(int)krn->kallsyms_markers);
		   return krn->kallsyms_markers;
	   }
   }

   return 0;
}

unsigned char* get_kallsyms_token_table(krninfo* krn)
{
	unsigned char * pdata;
	unsigned int offs = 0;
	unsigned int next =0;

	if(krn && krn->kallsyms_markers)
	{
		 krn->kallsyms_token_table = krn->kallsyms_markers;
		 pdata = krn->vmlinuzbuffer;

		 while(krn->kallsyms_token_table < krn->vmlinuz_size-8)
		 {
			 offs = *(unsigned int*)(pdata+(int)krn->kallsyms_token_table);
			 next = *(unsigned int*)(pdata+(int)krn->kallsyms_token_table+4);

			 if((next ==0 && next < offs))
			 {
				 krn->kallsyms_token_table = KERNEL_VARIBLE_ALIGN(krn->kallsyms_token_table+4);
				 printf("wonderful,found kallsyms_token_table offset 0x%x addr 0x%x \n",krn->kallsyms_token_table,krn->kernel_base+(int)krn->kallsyms_token_table);
				 return krn->kallsyms_token_table;
			 }
			 else if( abs(next-offs) > 0x10000)
			 {
				 krn->kallsyms_token_table = KERNEL_VARIBLE_ALIGN(krn->kallsyms_token_table+4);
				 printf("wonderful,found kallsyms_token_table offset 0x%x addr 0x%x \n",krn->kallsyms_token_table,krn->kernel_base+(int)krn->kallsyms_token_table);
				 return krn->kallsyms_token_table;
			 }
#ifndef __GNUC__
             (unsigned char*)krn->kallsyms_token_table +=4;
#else
			 krn->kallsyms_token_table = (unsigned char*)krn->kallsyms_token_table + 4;
#endif
		 }
	}

	return 0;
}

int get_kallsyms_token_index(krninfo* krn)
{
	int i;
	int n;
	unsigned char * pdata;
	char token_buffer[260];

	if(krn && krn->kallsyms_token_table)
	{
		krn->kallsyms_token_index = krn->kallsyms_token_table;
		pdata = krn->vmlinuzbuffer+(int)krn->kallsyms_token_index;
		//skip align
		if(*(unsigned int*)pdata == 0)
		{
           krn->kallsyms_token_index =  KERNEL_VARIBLE_ALIGN(krn->kallsyms_token_index+4);
		}

		pdata = krn->vmlinuzbuffer+(int)krn->kallsyms_token_index;

		for(i = 0;i<= 0x100;i++)
		{
			n = _strncpy_(token_buffer,pdata,260);
			if(n == 0 && i == 0x100)
			{
				krn->kallsyms_token_index = KERNEL_VARIBLE_ALIGN(krn->kallsyms_token_index);
				printf("excellent,found kallsyms_token_index offset 0x%x addr 0x%x \n",krn->kallsyms_token_index,krn->kernel_base+(int)krn->kallsyms_token_index);
				return krn->kallsyms_token_index;
			}
#ifndef __GNUC__ 
            (unsigned char*)krn->kallsyms_token_index += n+1;
#else
			krn->kallsyms_token_index = (unsigned char*)krn->kallsyms_token_index + n+1;
#endif
			pdata += n+1;
		}
	}

	return 0;
}


int get_symbol(krninfo* krn)
{
	int i;

	printf("search kallsyms_address ...\n");
	for(i = 0; i <sizeof(kernel_base)/sizeof(int);i++)
	{
		krn->kernel_base = kernel_base[i];

		if(get_kallsyms_addresses(krn))
		{
			return 	  get_kallsyms_nums(krn) &&
				get_kallsyms_markers(krn) && get_kallsyms_token_table(krn) &&
				get_kallsyms_token_index(krn);
		}
	}

	return 0;
}

char kallsyms_get_symbol_type(krninfo* krn,unsigned int off)
{
	int names = krn->kallsyms_names[off + 1];
	int token = krn->kallsyms_token_index[names];
	return krn->kallsyms_token_table[token];
}

unsigned long get_symbol_pos(krninfo* krn,unsigned long addr,  unsigned long *symbolsize,unsigned long *offset)
{
	unsigned long symbol_start = 0, symbol_end = 0;
	unsigned long i, low, high, mid;


	/* Do a binary search on the sorted kallsyms_addresses array. */
	low = 0;
	high = krn->kallsyms_num_syms;

	while (high - low > 1) {
		mid = low + (high - low) / 2;
		if (krn->kallsyms_addresses[mid] <= addr)
			low = mid;
		else
			high = mid;
	}

	/*
	 * Search for the first aliased symbol. Aliased
	 * symbols are symbols with the same address.
	 */
	while (low && krn->kallsyms_addresses[low-1] == krn->kallsyms_addresses[low])
		--low;

	symbol_start = krn->kallsyms_addresses[low];

	/* Search for next non-aliased symbol. */
	for (i = low + 1; i < krn->kallsyms_num_syms; i++) {
		if (krn->kallsyms_addresses[i] > symbol_start) {
			symbol_end =krn->kallsyms_addresses[i];
			break;
		}
	}

	if (symbolsize)
		*symbolsize = symbol_end - symbol_start;
	if (offset)
		*offset = addr - symbol_start;

	return low;
}

unsigned int kallsyms_expand_symbol(krninfo* krn,unsigned int off, char *result)
{
	int len, skipped_first = 0;
	const unsigned char *tptr, *data;

	/* Get the compressed symbol length from the first symbol byte. */
	data = &krn->kallsyms_names[off];
	len = *data;
	data++;

	/*
	 * Update the offset to return the offset for the next symbol on
	 * the compressed stream.
	 */
	off += len + 1;

	/*
	 * For every byte on the compressed symbol data, copy the table
	 * entry for that byte.
	 */
	while (len) {
		tptr = &krn->kallsyms_token_table[krn->kallsyms_token_index[*data]];
		data++;
		len--;

		while (*tptr) {
			if (skipped_first) {
				*result = *tptr;
				result++;
			} else
				skipped_first = 1;
			tptr++;
		}
	}

	*result = '\0';

	/* Return to offset to the next symbol. */
	return off;
}

void krn_varible_fix(krninfo* krn)
{
    if(krn)
	{
		krn->kallsyms_addresses=krn->vmlinuzbuffer+(int)krn->kallsyms_addresses;
		krn->kallsyms_names=krn->vmlinuzbuffer+(int)krn->kallsyms_names;
		krn->kallsyms_markers=krn->vmlinuzbuffer+(int)krn->kallsyms_markers;
		krn->kallsyms_token_table=krn->vmlinuzbuffer+(int)krn->kallsyms_token_table;
		krn->kallsyms_token_index=krn->vmlinuzbuffer+(int)krn->kallsyms_token_index;
	}
}

static unsigned int get_symbol_offset(krninfo* krn,unsigned long pos)
{
	const unsigned char *name;
	unsigned int i;
	int offs;

	offs = krn->kallsyms_markers[pos >> 8];

	name = &krn->kallsyms_names[offs];

	for (i = 0; i < (pos & 0xFF); i++)
		name = name + (*name) + 1;

	return name - krn->kallsyms_names;
}

int is_show_symbol(const char* symbol)
{
	int i;

    for(i = 0;i < sizeof(used_symbol)/sizeof(char*) ;i++)
	{
        if(strcmp(used_symbol[i],symbol) ==0 )
		{
			return 1;
		}
	}

	return 0;
}

char *__strrev(char *str)
{
	char *p1, *p2;

	if (! str || ! *str)
		return str;
	for (p1 = str, p2 = str + strlen(str) - 1; p2 > p1; ++p1, --p2)
	{
		*p1 ^= *p2;
		*p2 ^= *p1;
		*p1 ^= *p2;
	}
	return str;
}

int is_ioctl_sym(const char* symbol)
{
	int i;
	char sym[512];

	strncpy(sym,symbol,512);
	__strrev(sym);

	if(strncmp(sym,"ltcoi_",6) == 0)
	{
		return 1;
	}

	return 0;
}

int extract_kallsyms(const char* directory,krninfo* krn)
{
	FILE* fidc;
	unsigned long i;
	unsigned int pos,offs;
	char pathbuffer[260] ={0};
	char namebuf[128];
#ifdef _WIN32
    sprintf(pathbuffer,"%s\\kallsyms.idc",directory);
#else
    sprintf(pathbuffer,"%s/kallsyms.idc",directory);
#endif
	fidc = fopen(pathbuffer,"wb");
	if(fidc == 0)  return 0;
	fputs("#include <idc.idc>\n",fidc);
	fputs("static main(){\n",fidc);

	for (i = 0; i < krn->kallsyms_num_syms; i++)
	{
		pos = get_symbol_pos(krn,krn->kallsyms_addresses[i],0,0);//pos =i*4;
		offs = get_symbol_offset(krn,pos);
		kallsyms_expand_symbol(krn,offs, namebuf);
		if(is_show_symbol(namebuf))
		{
            printf("%.8x	%c	%s\n",krn->kallsyms_addresses[i],kallsyms_get_symbol_type(krn,offs),namebuf);
			if(sys_call_table_addr == 0 && strcmp(namebuf,"sys_call_table")==0)
				sys_call_table_addr = krn->kallsyms_addresses[i];
		}
		if(fdevice_log && is_ioctl_sym(namebuf))
		{
			memset(pathbuffer,0,260);
			sprintf(pathbuffer,"%.8x	%c	%s\r\n",krn->kallsyms_addresses[i],kallsyms_get_symbol_type(krn,offs),namebuf);
			fputs(pathbuffer,fdevice_log);
		}
		//printf("%.8x	%c	%s\n",krn->kallsyms_addresses[i],kallsyms_get_symbol_type(krn,offs),namebuf);
		sprintf(pathbuffer,"	MakeNameEx(0x%.8x, \"%s\", 0);\n",krn->kallsyms_addresses[i],namebuf);
		fputs(pathbuffer,fidc);
		memset(namebuf,0,128);
	}
	fputs("}\n",fidc);
	if(sys_call_table_addr)
	{
		memset(pathbuffer,0,260);
		sprintf(pathbuffer,"%.8x	T	sys_ni_call\r\n",sys_call_table_addr+271*4);
		printf("%s\n",pathbuffer);
	}
	fflush(fidc);
	fclose(fidc);

	return 1;
}

int extract_symbol(const char* directory,krninfo* krn)
{
	char path[260];

	if(g_save_ioctl_func)
	{
		sprintf(path,"%s/device_ioctl.txt",directory);
        fdevice_log = fopen(path,"wb");
	}

	if(get_symbol(krn))
	{
		printf("found all the kallsyms varibles succeed\n");
		krn_varible_fix(krn);
		extract_kallsyms(directory,krn);
		return 1;
	}

	printf("analyse kernel failed,exit\n");

	if(fdevice_log)
		fclose(fdevice_log);

	return 0;
}
