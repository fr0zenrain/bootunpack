#ifndef __BOOTUNPACK_H__
#define __BOOTUNPACK_H__

/*
 kallsyms varible declare sequence as follows:
 if sequence is confuse ,can't get the correct value;

 kallsyms_addresses[]
 int kallsyms_nums
 kallsyms_markers[]
 kallsyms_token_table[0x100];
 kallsyms_token_index[]

*/

#ifdef __MACH__
#define MAP_ANONYMOUS MAP_ANON
#endif

#define BOOT_MAGIC_SIZE   8
#define BOOT_NAME_SIZE   16
#define  BOOT_ARGS_SIZE  512

#define DEFAULT_KERNEL_BASE   0xc0008000
#define SEMC_KERNEL_BASE  0x80008000
#define COOLPAD_KERNEL_BASE  0xc0008180

#define KERNEL_VARIBLE_ALIGN(x)  ((((unsigned int)x)+0xf)&0xfffffff0)

enum compress
{
	UNKNOW,
	UNCOMPRESS,
	GZ,
	BZ2,
	LZMA,
	LZO,
	LZ4,
	XZ,
	TAR,
};

typedef struct _boot_img_hdr  
{  
	unsigned char magic[BOOT_MAGIC_SIZE];  
	unsigned  kernel_size;  
	unsigned  kernel_addr;  
	unsigned  ramdisk_size;  
	unsigned  ramdisk_addr;  
	unsigned  second_size;  
	unsigned  second_addr;  
	unsigned  tags_addr;  
	unsigned  page_size;  
	unsigned  unused[2];  
	unsigned  char  name[BOOT_NAME_SIZE] ;
	unsigned  char cmdline[BOOT_ARGS_SIZE];
	unsigned  id[8];//timestamp
}boot_img_hdr;


typedef struct _krninfo
{
	boot_img_hdr* boot_hdr;
	unsigned char* vmlinuzbuffer;
	unsigned int vmlinuz_size;
	unsigned char* ramdiskbuffer;
	unsigned int ramdisk_size;
	////////////////////////
	unsigned int kernel_base;
    unsigned int* kallsyms_addresses;
	unsigned int kallsyms_num_syms_offs;
	unsigned int kallsyms_num_syms;
	unsigned int* kallsyms_markers;
	unsigned short* kallsyms_token_index;
	unsigned char* kallsyms_token_table;
	unsigned char* kallsyms_names;
	/////////////////////////////
	unsigned int type;
	unsigned int kernel_offs;
}krninfo;



int get_gzip_offset(unsigned char* pdata,unsigned int size,int start_offs);
int extract_symbol(const char* directory,krninfo* krn);



#endif