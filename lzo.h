#ifndef __LZO_H__
#define __LZO_H__
/*
 *  LZO Public Kernel Interface
 *  A mini subset of the LZO real-time data compression library
 *
 *  Copyright (C) 1996-2005 Markus F.X.J. Oberhumer <markus@oberhumer.com>
 *
 *  The full LZO package can be found at:
 *  http://www.oberhumer.com/opensource/lzo/
 *
 *  Changed for kernel use by:
 *  Nitin Gupta <nitingupta910@gmail.com>
 *  Richard Purdie <rpurdie@openedhand.com>
 */
#define LZO_UINT32_C(c) (c##ULL)
#define LZO1X_MEM_COMPRESS	(16384 * sizeof(unsigned char *))
#define LZO1X_1_MEM_COMPRESS	LZO1X_MEM_COMPRESS

#define lzo1x_worst_compress(x) ((x) + ((x) / 16) + 64 + 3)

/* This requires 'workmem' of size LZO1X_1_MEM_COMPRESS */
int lzo1x_1_compress(const unsigned char *src, int src_len,
			unsigned char *dst, int *dst_len, void *wrkmem);

/* safe decompression with overrun testing */
int lzo1x_decompress_safe(const unsigned char *src, int src_len,
			unsigned char *dst, int *dst_len);


/*
 * Return values (< 0 = Error)
 */
#define LZO_E_OK			0
#define LZO_E_ERROR			(-1)
#define LZO_E_OUT_OF_MEMORY		(-2)
#define LZO_E_NOT_COMPRESSIBLE		(-3)
#define LZO_E_INPUT_OVERRUN		(-4)
#define LZO_E_OUTPUT_OVERRUN		(-5)
#define LZO_E_LOOKBEHIND_OVERRUN	(-6)
#define LZO_E_EOF_NOT_FOUND		(-7)
#define LZO_E_INPUT_NOT_CONSUMED	(-8)
#define LZO_E_NOT_YET_IMPLEMENTED	(-9)


#define get_unaligned(ptr) (*(ptr))
#define put_unaligned(val, ptr) ((void)( *(ptr) = (val) ))


#define lzo_init() __lzo_init_v2(0x1060,(int)sizeof(short),(int)sizeof(int),\
	(int)sizeof(long),(int)sizeof(unsigned int),(int)sizeof(unsigned int),\
	(int)sizeof(char*),(int)sizeof(char *),(int)sizeof(void*),\
	(int)sizeof(void*))

int __lzo_init_v2(unsigned,int,int,int,int,int,int,int,int,int);

#define LZO_MAX(a,b)        ((a) >= (b) ? (a) : (b))
#define LZO_MIN(a,b)        ((a) <= (b) ? (a) : (b))

/* header flags */
#define F_ADLER32_D     0x00000001L
#define F_ADLER32_C     0x00000002L
#define F_STDIN         0x00000004L
#define F_STDOUT        0x00000008L
#define F_NAME_DEFAULT  0x00000010L
#define F_DOSISH        0x00000020L
#define F_H_EXTRA_FIELD 0x00000040L
#define F_H_GMTDIFF     0x00000080L
#define F_CRC32_D       0x00000100L
#define F_CRC32_C       0x00000200L
#define F_MULTIPART     0x00000400L
#define F_H_FILTER      0x00000800L
#define F_H_CRC32       0x00001000L
#define F_H_PATH        0x00002000L
#define F_MASK          0x00003FFFL

/* operating system & file system that created the file [mostly unused] */
#define F_OS_FAT        0x00000000L         /* DOS, OS2, Win95 */
#define F_OS_AMIGA      0x01000000L
#define F_OS_VMS        0x02000000L
#define F_OS_UNIX       0x03000000L
#define F_OS_VM_CMS     0x04000000L
#define F_OS_ATARI      0x05000000L
#define F_OS_OS2        0x06000000L         /* OS2 */
#define F_OS_MAC9       0x07000000L
#define F_OS_Z_SYSTEM   0x08000000L
#define F_OS_CPM        0x09000000L
#define F_OS_TOPS20     0x0a000000L
#define F_OS_NTFS       0x0b000000L         /* Win NT/2000/XP */
#define F_OS_QDOS       0x0c000000L
#define F_OS_ACORN      0x0d000000L
#define F_OS_VFAT       0x0e000000L         /* Win32 */
#define F_OS_MFS        0x0f000000L
#define F_OS_BEOS       0x10000000L
#define F_OS_TANDEM     0x11000000L
#define F_OS_SHIFT      24
#define F_OS_MASK       0xff000000L

/* character set for file name encoding [mostly unused] */
#define F_CS_NATIVE     0x00000000L
#define F_CS_LATIN1     0x00100000L
#define F_CS_DOS        0x00200000L
#define F_CS_WIN32      0x00300000L
#define F_CS_WIN16      0x00400000L
#define F_CS_UTF8       0x00500000L         /* filename is UTF-8 encoded */
#define F_CS_SHIFT      20
#define F_CS_MASK       0x00f00000L

/* these bits must be zero */
#define F_RESERVED      ((F_MASK | F_OS_MASK | F_CS_MASK) ^ 0xffffffffL)
#define LZOP_VERSION    0x1030
#define ADLER32_INIT_VALUE  1
#define CRC32_INIT_VALUE    0

#if defined(ACC_OS_DOS16) && !defined(ACC_ARCH_I086PM)
#  define BLOCK_SIZE        (128*1024l)
#else
#  define BLOCK_SIZE        (256*1024l)
#endif
#define MAX_BLOCK_SIZE      (64*1024l*1024l)        /* DO NOT CHANGE */
/* LZO may expand uncompressible data by a small amount */
#define MAX_COMPRESSED_SIZE(x)  ((x) + (x) / 16 + 64 + 3)

/* align a char pointer on a boundary that is a multiple of `size' */
unsigned short __lzo_align_gap(const void* _ptr, unsigned int _size);
#define LZO_PTR_ALIGN_UP(_ptr,_size) \
	((_ptr) + (unsigned int) __lzo_align_gap((const void*)(_ptr),( unsigned int)(_size)))

/* deprecated - only for backward compatibility */
#define LZO_ALIGN(_ptr,_size) LZO_PTR_ALIGN_UP(_ptr,_size)

enum {
	M_LZO1X_1     =     1,
	M_LZO1X_1_15  =     2,
	M_LZO1X_999   =     3,
	M_NRV1A       =  0x1a,
	M_NRV1B       =  0x1b,
	M_NRV2A       =  0x2a,
	M_NRV2B       =  0x2b,
	M_NRV2D       =  0x2d,
	M_ZLIB        =   128,

	M_UNUSED
};

#pragma pack(1)
typedef struct
{
	unsigned short version;
	unsigned short lib_version;
	unsigned short version_needed_to_extract;
	unsigned char method;
	unsigned char level;
	unsigned int flags;
	unsigned int filter;
	unsigned int mode;
	unsigned int mtime_low;
	unsigned int mtime_high;
	unsigned int header_checksum;

	unsigned int extra_field_len;
	unsigned int extra_field_checksum;

	/* info */
	const char *method_name;

	char name[255+1];
}header_t;

typedef struct
{
    /* public */
    unsigned char*   mb_mem;
    unsigned int   mb_size;
    /* private */
    unsigned char*   mb_mem_alloc;
    unsigned int  mb_size_alloc;
    unsigned int  mb_align;
    /* the following fields are not yet used but may prove useful for
     * adding new algorithms */
    unsigned int  mb_flags;
    unsigned int  mb_id;
    unsigned int  mb_len;
    unsigned int  mb_adler32;
    unsigned int  mb_crc32;
}mblock_t;

union lzo_config_check_union {
	unsigned int a[2];
	unsigned char b[2*LZO_MAX(8,sizeof(unsigned int))];
#ifndef __GNUC__
	unsigned __int64 c[2];
#else
    unsigned long long c[2];
#endif
};

#pragma pack()

void free_mem();
unsigned short  get_be16(const unsigned char *b);
unsigned int get_be32(const unsigned char *b);
unsigned int lzo_crc32(unsigned int c, const unsigned char* buf, unsigned int len);
int alloc_mem(unsigned int s1, unsigned int s2, unsigned int w);
int get_lzo_dataoffset(unsigned char* pdata,int offset,int size);
int lzo_decompress(unsigned char* pdata, int offset,const header_t *h,unsigned char* pbuffer);


#endif
