// krnsym_extra.cpp : Defines the entry point for the console application.
//

#include "stdio.h"
#include "zlib.h"
#include "bootunpack.h"
#include "lzo.h"
#include "lz4/lz4.h"
#ifdef _WIN32
#include "windows.h"
#pragma comment(lib,"zlib.lib")
#else
#include <sys/mman.h>
#endif

extern unsigned int lzo_adler32(unsigned int adler, unsigned char* buf, int len);


int g_save_kernel = 0;
int g_save_symbol = 0;
int g_save_ioctl_func = 0;

const char* PathRemoveFileSpec(char* path)
{
	int i;
    size_t length = strlen(path);

	for(i = length ;i > 0 ;i--)
	{
#ifdef _WIN32
		if(path[i] =='\\')

#else
        if(path[i] =='/')
#endif
		{
			path[i] =0;
			break;
		}

	}

	return path;
}


int gzip_decode(void* pbufferin,int bufferin_size,void* pbufferout,int bufferoutsize)
{
	int ret;
	z_stream z;

	memset(&z,0,sizeof(z_stream));

	inflateInit2(&z, 16+MAX_WBITS);
	z.avail_in = bufferin_size;
	z.next_in = pbufferin;
	z.avail_out = bufferoutsize;
	z.next_out = pbufferout;

	ret = inflate(&z,2);
	if(ret == Z_OK || ret == Z_STREAM_END)
	{
		inflateEnd(&z);
		return  z.total_out;
	}

	return 0;
}

int gzdecode_kernel(unsigned char* pdata,int size,int vmlinuz_offs,int compress_size,krninfo* krn)
{
	if(vmlinuz_offs && compress_size && krn)
	{
		krn->vmlinuz_size = compress_size*4;//assume

#ifdef _WIN32
		krn->vmlinuzbuffer = (unsigned char*)VirtualAlloc(0,krn->vmlinuz_size,MEM_COMMIT,PAGE_READWRITE);
#else
        krn->vmlinuzbuffer = (unsigned char*)mmap(0,krn->vmlinuz_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS ,0,0);
#endif
		if(krn->vmlinuzbuffer)
		{
			memset(krn->vmlinuzbuffer,0,krn->vmlinuz_size);
			krn->vmlinuz_size = gzip_decode(pdata+vmlinuz_offs,compress_size,krn->vmlinuzbuffer,krn->vmlinuz_size);
			if(krn->vmlinuz_size == 0)
			{
#ifdef _WIN32
				VirtualFree(krn->vmlinuzbuffer,krn->vmlinuz_size,MEM_RELEASE);
#else
				munmap(krn->vmlinuzbuffer,krn->vmlinuz_size);
#endif

				return 0;
			}
		}
	}

    return krn->vmlinuz_size;
}
#include "lzo.h"

int lzodecode_kernel(unsigned char* pdata,int size,int vmlinuz_offs,int compress_size,krninfo* krn)
{
	int ret;

	if(vmlinuz_offs && compress_size && krn)
	{
		krn->vmlinuz_size = compress_size*2;//assume

#ifdef _WIN32
		krn->vmlinuzbuffer = (unsigned char*)VirtualAlloc(0,krn->vmlinuz_size,MEM_COMMIT,PAGE_READWRITE);
#else
		krn->vmlinuzbuffer = (unsigned char*)mmap(0,krn->vmlinuz_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS ,0,0);
#endif
		if(krn->vmlinuzbuffer)
		{
			memset(krn->vmlinuzbuffer,0,krn->vmlinuz_size);
			ret = lzo1x_decompress_safe(pdata+vmlinuz_offs,compress_size,krn->vmlinuzbuffer,&krn->vmlinuz_size);
			if(ret != 0)
			{
#ifdef _WIN32
				VirtualFree(krn->vmlinuzbuffer,krn->vmlinuz_size,MEM_RELEASE);
#else
				munmap(krn->vmlinuzbuffer,krn->vmlinuz_size);
#endif

				krn->vmlinuz_size = 0;
				return 0;
			}
		}
	}

	return krn->vmlinuz_size;
}


int decode_ramdisk(unsigned char* pdata,int size,int ramdisk_offs,int compress_size,krninfo* krn)
{
	if(ramdisk_offs && compress_size )
	{
       krn->ramdiskbuffer = malloc(compress_size*4);
	   if(krn->ramdiskbuffer)
	   {
		   memset(krn->ramdiskbuffer,0,compress_size*4);
		   krn->ramdisk_size = gzip_decode(pdata+ramdisk_offs,compress_size,krn->ramdiskbuffer,compress_size*4);
		   if(krn->ramdisk_size == 0)
		   {
			   free(krn->ramdiskbuffer);
			   printf("ramdisk uncompress failed\n");
			   return 0;
		   }
	   }
	}

	return  krn->ramdisk_size;
}

char * _strstr_(const char *in,size_t size, const char *str)
{
	char c;
	size_t len;
	const char* end;

	c = *str++;
	if (!c)
		return (char *) in;

	len = strlen(str);
	end = in+size-len;
	do {
		char sc;

		do {
			sc = *in++;
			if (in > end)
				return 0;
		} while (sc != c);
	} while (strncmp(in, str, len) != 0);

	return (char *) (in - 1);
}

int is_android_bootimg(unsigned char* pdata,int size)
{
	return pdata && strncmp(pdata,"ANDROID!",8) == 0 ;
}

int is_elf(unsigned char* pdata,int size)
{
	return pdata && strncmp(pdata,"\x7f\x45\x4c\x46",4) ==0;//sony x50h is ELF
}

int is_zimage(unsigned char* pdata,int size)
{
	if(size > 0x1000)
	{
		return *(unsigned int*)pdata == 0xe1a00000 && *(unsigned int*)(pdata+8)== 0xe1a00000 &&
			*(unsigned int*)(pdata+16)== 0xe1a00000 && *(unsigned int*)(pdata+20)== 0xe1a00000;
	}

	return 0;
}


void show_version(unsigned char* vmlinuz,int size)
{
   const char* ver;
   if(vmlinuz && size)
   {
	   ver = _strstr_(vmlinuz,size,"Linux version");
	   if(ver)
		   printf("%s\n",ver);
   }
}

int  dump(unsigned char* pdata,int size,const char* name)
{
	FILE* fd;

	if(pdata && size)
	{

		fd = fopen(name,"wb");
		if(fd == 0)
		{
			printf("dump failed\n");
			return 0;
		}
		fwrite(pdata,1,size,fd);
		fclose(fd);
		return 1;
	}

	return 0;
}

void freeimg(krninfo* krn)
{
#ifdef _WIN32
	VirtualFree(krn->vmlinuzbuffer,krn->vmlinuz_size,MEM_RELEASE);
#else
	munmap(krn->vmlinuzbuffer,krn->vmlinuz_size);
#endif

   if(krn->ramdiskbuffer)
	   free(krn->ramdiskbuffer);
}

int is_vmlinuz(unsigned char* pdata,int size)
{
    if(pdata && size)
	{
		if(strncmp(pdata,"\xd3\xf0\x21\xe3\x10\x9f\x10\xee",8)==0||
			strncmp(pdata,"\x46\x42\x00\xeb\x00\x90\x0f\xe1",8)==0 || //mx4
			strncmp(pdata,"\x46\x20\x04\xeb\x00\x90\x0f\xe1",8)==0 || //samsung
			strncmp(pdata,"\x76\x20\x04\xeb\x00\x90\x0f\xe1",8)==0 ||
			strncmp(pdata,"\x3e\x2d\x04\xeb\x00\x90\x0f\xe1",8)==0
			)
			return 1;

	}

	return 0;
}

int get_ramdisk_offset(unsigned char* pdata,unsigned int size)
{
	int offset ;

	for(offset = size -4;offset > 0x800;offset--)
	{
		if(*(unsigned int*)(pdata+offset) == 0x088b1f)
		{
			return offset;
		}
	}

	return 0;
}

//some bootimg have no ramdisk

int get_gzip_offset(unsigned char* pdata,unsigned int size,int start_offset)
{
	unsigned int offset = start_offset;

	if(pdata ==0  )
		return 0;

	for(;offset < size - 4;offset++)
	{
		if(*(unsigned int*)(pdata+offset) == 0x088b1f)
		{
			return offset;
		}
	}

	return 0;
}

int gzip_decode_kernel(unsigned char* image ,unsigned int size,krninfo* krn)
{
	unsigned int compress_size;
	int gzip_offs =0;

	gzip_offs = get_gzip_offset(image,size,0x800);
	if(gzip_offs)
	{
		compress_size = size - gzip_offs;
		if(gzdecode_kernel(image,size,gzip_offs,compress_size,krn)==0)
		{
			return 0;
		}
		if(is_vmlinuz(krn->vmlinuzbuffer,krn->vmlinuz_size))
		{
			krn->kernel_offs = gzip_offs;
			return 1;
		}
		else
		{
			gzip_offs = get_gzip_offset(image,size,gzip_offs+4);
			if(gzip_offs)
			{
				compress_size = size - gzip_offs;
				if(gzdecode_kernel(image,size,gzip_offs,compress_size,krn)==0)
				{
					return 0;
				}
				if(is_vmlinuz(krn->vmlinuzbuffer,krn->vmlinuz_size))
				{
					krn->kernel_offs = gzip_offs;
					return 1;
				}
			}
		}
	}

	return 0;
}


int get_lz4_offset(unsigned char* pdata,unsigned int size,int start_offset)
{
	unsigned int offset = start_offset;

	if(pdata ==0  )
		return 0;

	for(;offset < size - 4;offset++)
	{
		if(*(unsigned int*)(pdata+offset) == 0x184C2102)
		{
			return offset;
		}
	}

	return 0;
}

void err_msg(char* msg)
{
}

int lz4_decode_kernel(unsigned char* image ,unsigned int size,krninfo* krn)
{
	int ok = 0;
	unsigned int posp;
	unsigned int outsize;
	int lz4_offs =0;

	lz4_offs = get_lz4_offset(image,size-lz4_offs,lz4_offs);
	while(lz4_offs)
	{

		krn->vmlinuz_size = (size - lz4_offs)*4;//assume

#ifdef _WIN32
		krn->vmlinuzbuffer = (unsigned char*)VirtualAlloc(0,krn->vmlinuz_size,MEM_COMMIT,PAGE_READWRITE);
#else
		krn->vmlinuzbuffer = (unsigned char*)mmap(0,krn->vmlinuz_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS ,0,0);
#endif
		if(krn->vmlinuzbuffer)
		{
			ok = unlz4(image+lz4_offs,size-lz4_offs,0,0,krn->vmlinuzbuffer,&posp,&outsize,err_msg);

			//because we don't know the size,so it can not return 0
			if(ok  != 0 && posp < 4*1024*1024)
			{
#ifdef _WIN32
				VirtualFree(krn->vmlinuzbuffer,krn->vmlinuz_size,MEM_RELEASE);
#else
				munmap(krn->vmlinuzbuffer,krn->vmlinuz_size);
#endif

				krn->vmlinuz_size = 0;
			}
		}

		if(is_vmlinuz(krn->vmlinuzbuffer,krn->vmlinuz_size))
		{
			krn->kernel_offs = lz4_offs;
			krn->vmlinuz_size = outsize;
			return 1;
		}

		lz4_offs = get_lz4_offset(image,size-lz4_offs-4,lz4_offs+4);
	}

	return 0;
}


int lzo_get_method(header_t *h)
{
	/* check method */
	if (h->method == M_LZO1X_1)
	{
		h->method_name = "LZO1X-1";
		if (h->level == 0)
			h->level = 3;
	}
	else if (h->method == M_LZO1X_1_15)
	{
		h->method_name = "LZO1X-1(15)";
		if (h->level == 0)
			h->level = 1;
	}
	else if (h->method == M_LZO1X_999)
	{
		static char s[11+1] = "LZO1X-999  ";
		s[9] = 0;
		if (h->level == 0)
			h->level = 9;
		else if (h->version >= 0x0950 && h->lib_version >= 0x1020)
		{
			s[9] = '/';
			s[10] = (char) (h->level + '0');
		}
		h->method_name = s;
	}
	else
		return -1;      /* not a LZO method */

	/* check compression level */
	if (h->level < 1 || h->level > 9)
		return 15;

	return 0;
}

int get_lzopdata_offset(unsigned char* pdata,unsigned int size,int start_offset,header_t* header)
{
	int k;
	unsigned char l;
	unsigned int checksum;
	unsigned int adler32 = ADLER32_INIT_VALUE;
	unsigned int crc32 =  CRC32_INIT_VALUE;

	char* p = pdata+start_offset+9;
	char* q=p;

	if(pdata ==0 || start_offset == 0)
		return 0;

	header->version = get_be16(p);p+=2;
	header->lib_version =  get_be16(p);p+=2;
	if(header->version > 0x940)
	{
		header->version_needed_to_extract = get_be16(p);p+=2;
		if(header->version_needed_to_extract > LZOP_VERSION || header->version_needed_to_extract  < 0x900)
			return 0;

	}
	header->method = *p++;
	if (header->version >= 0x0940)
		header->level = *p++;
	header->flags = get_be32(p);p+=4;

	if (header->flags & F_H_FILTER)
	{
		header->filter = get_be32(p);p+=4;
	}

	header->mode=get_be32(p);p+=4;

	if (header->flags & F_STDIN) /* do not use mode from stdin compression */
		header->mode = 0;

	header->mtime_low = header->mode=get_be32(p);p+=4;

	if (header->version >= 0x0940)
	{
		header->mtime_high = get_be32(p);p+=4;
	}
	if (header->version < 0x0120)
	{
		if (header->mtime_low == 0xffffffff)
			header->mtime_low = 0;
		header->mtime_high = 0;
	}

	l =*p++;
	if (l > 0) {
		char name[255+1];
		if (memcpy(name,p,l) != l)
			name[l] = 0;

	}

	header->header_checksum = get_be32(p);
	adler32 = lzo_adler32(adler32,q,p-q);
	checksum = (header->flags & F_H_CRC32) ? crc32 : adler32;

	if(checksum !=header->header_checksum)
	{
		return 0;
	}

	p+=4;

	if(lzo_get_method(header)!=0)
	{
		return 0;
	}

	/* skip extra field [not used yet] */
	if (header->flags & F_H_EXTRA_FIELD)
	{
		header->extra_field_len = get_be32(p);p+=4;
		for (k = 0; k < header->extra_field_len; k++)
			p++;
		checksum = (header->flags & F_H_CRC32) ? crc32 : adler32;
		header->extra_field_checksum = get_be32(p);

		if (header->extra_field_checksum != checksum)
			return 3;
	}

	return (p-q)+start_offset+9;
}

int get_lzop_offset(unsigned char* pdata,unsigned int size,int start_offset)
{
	unsigned int offset  = start_offset;

	if(pdata ==0 )
		return 0;

	for(;offset < size - 4;offset++)
	{
		if(*(unsigned int*)(pdata+offset)== 0x4f5a4c89)
		{
			return offset;
		}
	}

	return 0;
}

int lzop_decode_kernel(unsigned char* image ,unsigned int size,krninfo* krn)
{
	unsigned int data_offset;
	int lzop_offs =0;
	int block_size = BLOCK_SIZE;

	header_t header;
	lzop_offs = get_lzop_offset(image,size,0x800);
	while(lzop_offs)
	{
		data_offset = get_lzopdata_offset(image,size,lzop_offs,&header);
		if(data_offset)
		{
			krn->vmlinuz_size = (size - data_offset)*2;//assume

#ifdef _WIN32
			krn->vmlinuzbuffer = (unsigned char*)VirtualAlloc(0,krn->vmlinuz_size,MEM_COMMIT,PAGE_READWRITE);
#else
			krn->vmlinuzbuffer = (unsigned char*)mmap(0,krn->vmlinuz_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS ,0,0);
#endif
			if(krn->vmlinuzbuffer)
			{
				memset(krn->vmlinuzbuffer,0,krn->vmlinuz_size);
				alloc_mem(0, MAX_COMPRESSED_SIZE(block_size), 0);
				krn->vmlinuz_size = lzo_decompress(image,data_offset,&header,krn->vmlinuzbuffer);

				if(krn->vmlinuz_size  == 0)
				{
					free_mem();
#ifdef _WIN32
					VirtualFree(krn->vmlinuzbuffer,krn->vmlinuz_size,MEM_RELEASE);
#else
					munmap(krn->vmlinuzbuffer,krn->vmlinuz_size);
#endif

					krn->vmlinuz_size = 0;
					return 0;
				}
			}
			free_mem();
			if(is_vmlinuz(krn->vmlinuzbuffer,krn->vmlinuz_size))
			{
				krn->kernel_offs = lzop_offs;
				return 1;
			}
		}

		lzop_offs = get_lzop_offset(image,size,lzop_offs+4);
	}


	return 0;
}

int guess_offset(unsigned char* data,unsigned int size)
{
	int offset = 0;

	if(is_zimage(data+0x800,size))
	{
		offset = 0x800;
	}
	else if(is_vmlinuz(data+0x1000,size))
	{
		offset = 0x800;
	}

	return offset;
}

int load_bootimg(const char* path)
{
	int size;
	FILE* fd ;
	krninfo krn;
	boot_img_hdr* hdr;
	unsigned char* image;
	int vmlinuz_offs =0;
	int ramdisk_offs =0;
	unsigned int compress_size;
	char pathbuffer[260]={0};

	fd = fopen(path,"rb");
	if(fd ==0) return 0;
	fseek(fd,0,SEEK_END);
	size = ftell(fd);

	image = (unsigned char*)malloc(size);
	if(image ==0)
	{
        fclose(fd);
		return 0;
	}

	fseek(fd,0,SEEK_SET);
	fread(image,1,size,fd);
	fclose(fd);

	memset(&krn,0,sizeof(krninfo));
	if(is_zimage(image,size))
	{
		printf("looks like zImage\n");
		goto zimg;
	}

    if(!is_android_bootimg(image,size) && !is_elf(image,size))
	{
		printf("not an Android boot.img\n");
		free(image);
		return 0;
	}

	hdr = (boot_img_hdr*)image;
	if(strlen(hdr->cmdline))
	{
		printf("%s\n\n",hdr->cmdline);
	}

	krn.boot_hdr = hdr;

zimg:
	if(_strstr_(image+0xa00,size-0xa00,"Linux version"))
	{
		//uncompressed
        vmlinuz_offs = 0xa00;
		krn.type = UNCOMPRESS;
		printf("kenerl compress method: none\n");

        ramdisk_offs = get_ramdisk_offset(image,size);
		if(ramdisk_offs)
		{
			krn.vmlinuz_size = ramdisk_offs-vmlinuz_offs;
		}

#ifdef _WIN32
		krn.vmlinuzbuffer = (unsigned char*)VirtualAlloc(0,krn.vmlinuz_size,MEM_COMMIT,PAGE_READWRITE);
#else
		krn.vmlinuzbuffer = (unsigned char*)mmap(0,krn.vmlinuz_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS ,0,0);
#endif
		if(krn.vmlinuzbuffer)
		{
			memcpy(krn.vmlinuzbuffer,image+vmlinuz_offs,krn.vmlinuz_size);
		}
	}
	else
	{
		if(gzip_decode_kernel(image,size,&krn))
		{
            krn.type = GZ;
			printf("kenerl compress method: gz\n");
		}
		else if(lzop_decode_kernel(image,size,&krn))
		{
			krn.type = LZO;
			printf("kenerl compress method: lzo\n");
		}
		else if(lz4_decode_kernel(image,size,&krn))
		{
			krn.type = LZ4;
			printf("kenerl compress method: lz4\n");
		}
		else
		{
			krn.type = UNKNOW;

	        krn.kernel_offs = guess_offset(image,size);
			if(krn.kernel_offs)
			{
				krn.type = UNCOMPRESS;
				krn.vmlinuzbuffer = image + krn.kernel_offs;
				krn.vmlinuz_size = hdr->kernel_size;
			}

	
			
			printf("not found packed vmlinuz or unknow compress method\n");
		}
	}

	show_version(krn.vmlinuzbuffer,krn.vmlinuz_size);
	PathRemoveFileSpec(path);

	if(g_save_kernel)
	{
#ifdef _WIN32
		sprintf(pathbuffer,"%s\\vmlinuz",path);
#else
		sprintf(pathbuffer,"%s/vmlinuz",path);
#endif
		dump(krn.vmlinuzbuffer,krn.vmlinuz_size,pathbuffer);
		if(krn.type)
			printf("vmlinuz dump ok\n\n");
#ifdef _WIN32
		sprintf(pathbuffer,"%s\\ramdisk",path);
#else
		sprintf(pathbuffer,"%s/ramdisk",path);
#endif
		ramdisk_offs = get_ramdisk_offset(image,size);
		if(ramdisk_offs)
		{
			compress_size = ramdisk_offs?size-ramdisk_offs:0;
			decode_ramdisk(image,size,ramdisk_offs,compress_size,&krn);
			if(strncmp(krn.ramdiskbuffer,"070701",6) == 0)
			{
				dump(krn.ramdiskbuffer,krn.ramdisk_size,pathbuffer);
				printf("ramdisk dump ok\n\n");
			}
			else
			{
                printf("have no ramdisk \n\n");
			}
		}
	}
	if( g_save_symbol)
	{
		extract_symbol(path,&krn);
	}

	freeimg(&krn);
	free(image);
	return 1;
}


void usage()
{
	printf("Android boot.img analyzer 1.5\n");
	printf("usage: image path option [...]\n");
	printf("-f save ioctl symbol\n");
	printf("-e save vmlinuz and ramdisk from image\n");
	printf("-s save symbols as idc script format\n");
	

}
int main(int argc, char* argv[])
{
	int i;
	const char* p = 0;
	char path[260]={0};

	if(argc < 2 )
	{
		usage();
		return 0;
	}

	for (i = 1; i < argc; i++ )
	{
		p = argv[i];

		if (*p == '-' )
		{
			p++;

			switch (toupper(*p))
			{
			case 'E':
			case 'e':
				g_save_kernel = 1;
				break;
			case 'S':
			case 's':
				g_save_symbol = 1;
				break;
			case 'F':
			case 'f':
				g_save_ioctl_func = 1;
				break;
			default:
				usage();
				return 0;
			}
		}
	}

	for ( i = 1; i < argc; i ++)
	{
		p = argv[i];
		if (*p == '-')	// skip option
			continue;
#ifdef _WIN32
		GetFullPathName(p, 260, path, 0);
#else
        realpath(p,path);
#endif
	}

	return load_bootimg(path);
}
