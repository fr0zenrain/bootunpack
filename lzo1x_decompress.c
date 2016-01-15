/*
 *  LZO1X Decompressor from MiniLZO
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
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "lzo.h"

#define M2_MAX_OFFSET 0x800
#define ALIGN_SIZE    4096

#define HAVE_IP(x, ip_end, ip) ((size_t)(ip_end - ip) < (x))
#define HAVE_OP(x, op_end, op) ((size_t)(op_end - op) < (x))
#define HAVE_LB(m_pos, out, op) (m_pos < out || m_pos >= op)

#define COPY4(dst, src)	\
		put_unaligned(get_unaligned((const unsigned int *)(src)), (unsigned int *)(dst))

static const unsigned int block_size = BLOCK_SIZE;
static mblock_t blocks[2];
static mblock_t wrkmem;

const unsigned char lzop_magic[9] =
{ 0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };

#define LZO_BASE 65521u /* largest prime smaller than 65536 */
#define LZO_NMAX 5552

#define LZO_DO1(buf,i)  s1 += buf[i]; s2 += s1
#define LZO_DO2(buf,i)  LZO_DO1(buf,i); LZO_DO1(buf,i+1)
#define LZO_DO4(buf,i)  LZO_DO2(buf,i); LZO_DO2(buf,i+2)
#define LZO_DO8(buf,i)  LZO_DO4(buf,i); LZO_DO4(buf,i+4)
#define LZO_DO16(buf,i) LZO_DO8(buf,i); LZO_DO8(buf,i+8)

unsigned short get_unaligned_le16(const unsigned char *p)
{
        return p[0] | p[1] << 8;
}


unsigned int get_unaligned_le32(const unsigned char *p)
{
	return *(unsigned int*)p;
}

unsigned short  get_be16(const unsigned char *b)
{
	unsigned short  v;

	v  = (unsigned short ) b[1] <<  0;
	v |= (unsigned short ) b[0] <<  8;
	return v;
}

unsigned int get_be32(const unsigned char *b)
{
	unsigned int  v;

	v  = (unsigned int) b[3] <<  0;
	v |= (unsigned int) b[2] <<  8;
	v |= (unsigned int) b[1] << 16;
	v |= (unsigned int) b[0] << 24;
	return v;
}

static void do_init(mblock_t* m, unsigned int size, unsigned int align)
{
	memset(m,0,sizeof(*m));
	m->mb_size = size;
	m->mb_align = (align > 1) ? align : 1;
	
	m->mb_adler32 = ADLER32_INIT_VALUE;
	m->mb_crc32 = CRC32_INIT_VALUE;
}

void mb_free(mblock_t*  m)
{
	free(m->mb_mem_alloc);
	memset(m,0,sizeof(*m));
}


int mb_alloc(mblock_t* m, unsigned int size, unsigned int align)
{
	do_init(m,size,align);
	if (m->mb_size == 0)
		return 1;

	m->mb_size_alloc = m->mb_size + m->mb_align - 1;
	m->mb_mem_alloc = (unsigned char *) malloc(m->mb_size_alloc);
	if (m->mb_mem_alloc == NULL)
		return 0;
	memset(m->mb_mem_alloc, 0, m->mb_size_alloc);

	m->mb_mem = m->mb_mem_alloc;

	return 1;
}

void free_mem()
{
	mb_free(&wrkmem);
	mb_free(&blocks[1]);
	mb_free(&blocks[0]);
}

int alloc_mem(unsigned int s1, unsigned int s2, unsigned int w)
{
	int r = 1;

	r &= mb_alloc(&blocks[0], s1, ALIGN_SIZE);
	r &= mb_alloc(&blocks[1], s2, ALIGN_SIZE);
	r &= mb_alloc(&wrkmem, w,  ALIGN_SIZE);
	if (!r)
		free_mem();
	return r;
}

unsigned int lzo_adler32(unsigned int adler, unsigned char* buf, int len)
{
	unsigned int s1 = adler & 0xffff;
	unsigned int s2 = (adler >> 16) & 0xffff;
	unsigned k;

	if (buf == 0)
		return 1;

	while (len > 0)
	{
		k = len < LZO_NMAX ? (unsigned short) len : LZO_NMAX;
		len -= k;
		if (k >= 16) do
		{
			LZO_DO16(buf,0);
			buf += 16;
			k -= 16;
		} while (k >= 16);
		if (k != 0) do
		{
			s1 += *buf++;
			s2 += s1;
		} while (--k > 0);
		s1 %= LZO_BASE;
		s2 %= LZO_BASE;
	}
	return (s2 << 16) | s1;
}

int lzo1x_decompress_safe(const unsigned char *in, int in_len,
						  unsigned char *out, int *out_len)
{
	const unsigned char * const ip_end = in + in_len;
	unsigned char * const op_end = out + *out_len;
	const unsigned char *ip = in, *m_pos;
	unsigned char *op = out;
	size_t t;

	*out_len = 0;

	if (*ip > 17) {
		t = *ip++ - 17;
		if (t < 4)
			goto match_next;
		if (HAVE_OP(t, op_end, op))
			goto output_overrun;
		if (HAVE_IP(t + 1, ip_end, ip))
			goto input_overrun;
		do {
			*op++ = *ip++;
		} while (--t > 0);
		goto first_literal_run;
	}

	while ((ip < ip_end)) {
		t = *ip++;
		if (t >= 16)
			goto match;
		if (t == 0) {
			if (HAVE_IP(1, ip_end, ip))
				goto input_overrun;
			while (*ip == 0) {
				t += 255;
				ip++;
				if (HAVE_IP(1, ip_end, ip))
					goto input_overrun;
			}
			t += 15 + *ip++;
		}
		if (HAVE_OP(t + 3, op_end, op))
			goto output_overrun;
		if (HAVE_IP(t + 4, ip_end, ip))
			goto input_overrun;

		COPY4(op, ip);
		op += 4;
		ip += 4;
		if (--t > 0) {
			if (t >= 4) {
				do {
					COPY4(op, ip);
					op += 4;
					ip += 4;
					t -= 4;
				} while (t >= 4);
				if (t > 0) {
					do {
						*op++ = *ip++;
					} while (--t > 0);
				}
			} else {
				do {
					*op++ = *ip++;
				} while (--t > 0);
			}
		}

first_literal_run:
		t = *ip++;
		if (t >= 16)
			goto match;
		m_pos = op - (1 + M2_MAX_OFFSET);
		m_pos -= t >> 2;
		m_pos -= *ip++ << 2;

		if (HAVE_LB(m_pos, out, op))
			goto lookbehind_overrun;

		if (HAVE_OP(3, op_end, op))
			goto output_overrun;
		*op++ = *m_pos++;
		*op++ = *m_pos++;
		*op++ = *m_pos;

		goto match_done;

		do {
match:
			if (t >= 64) {
				m_pos = op - 1;
				m_pos -= (t >> 2) & 7;
				m_pos -= *ip++ << 3;
				t = (t >> 5) - 1;
				if (HAVE_LB(m_pos, out, op))
					goto lookbehind_overrun;
				if (HAVE_OP(t + 3 - 1, op_end, op))
					goto output_overrun;
				goto copy_match;
			} else if (t >= 32) {
				t &= 31;
				if (t == 0) {
					if (HAVE_IP(1, ip_end, ip))
						goto input_overrun;
					while (*ip == 0) {
						t += 255;
						ip++;
						if (HAVE_IP(1, ip_end, ip))
							goto input_overrun;
					}
					t += 31 + *ip++;
				}
				m_pos = op - 1;
				m_pos -= get_unaligned_le16(ip) >> 2;
				ip += 2;
			} else if (t >= 16) {
				m_pos = op;
				m_pos -= (t & 8) << 11;

				t &= 7;
				if (t == 0) {
					if (HAVE_IP(1, ip_end, ip))
						goto input_overrun;
					while (*ip == 0) {
						t += 255;
						ip++;
						if (HAVE_IP(1, ip_end, ip))
							goto input_overrun;
					}
					t += 7 + *ip++;
				}
				m_pos -= get_unaligned_le16(ip) >> 2;
				ip += 2;
				if (m_pos == op)
					goto eof_found;
				m_pos -= 0x4000;
			} else {
				m_pos = op - 1;
				m_pos -= t >> 2;
				m_pos -= *ip++ << 2;

				if (HAVE_LB(m_pos, out, op))
					goto lookbehind_overrun;
				if (HAVE_OP(2, op_end, op))
					goto output_overrun;

				*op++ = *m_pos++;
				*op++ = *m_pos;
				goto match_done;
			}

			if (HAVE_LB(m_pos, out, op))
				goto lookbehind_overrun;
			if (HAVE_OP(t + 3 - 1, op_end, op))
				goto output_overrun;

			if (t >= 2 * 4 - (3 - 1) && (op - m_pos) >= 4) {
				COPY4(op, m_pos);
				op += 4;
				m_pos += 4;
				t -= 4 - (3 - 1);
				do {
					COPY4(op, m_pos);
					op += 4;
					m_pos += 4;
					t -= 4;
				} while (t >= 4);
				if (t > 0)
					do {
						*op++ = *m_pos++;
					} while (--t > 0);
			} else {
copy_match:
				*op++ = *m_pos++;
				*op++ = *m_pos++;
				do {
					*op++ = *m_pos++;
				} while (--t > 0);
			}
match_done:
			t = ip[-2] & 3;
			if (t == 0)
				break;
match_next:
			if (HAVE_OP(t, op_end, op))
				goto output_overrun;
			if (HAVE_IP(t + 1, ip_end, ip))
				goto input_overrun;

			*op++ = *ip++;
			if (t > 1) {
				*op++ = *ip++;
				if (t > 2)
					*op++ = *ip++;
			}

			t = *ip++;
		} while (ip < ip_end);
	}

	*out_len = op - out;
	return LZO_E_EOF_NOT_FOUND;

eof_found:
	*out_len = op - out;
	return (ip == ip_end ? LZO_E_OK :
		(ip < ip_end ? LZO_E_INPUT_NOT_CONSUMED : LZO_E_INPUT_OVERRUN));
input_overrun:
	*out_len = op - out;
	return LZO_E_INPUT_OVERRUN;

output_overrun:
	*out_len = op - out;
	return LZO_E_OUTPUT_OVERRUN;

lookbehind_overrun:
	*out_len = op - out;
	return LZO_E_LOOKBEHIND_OVERRUN;
}

int lzo_decompress(unsigned char* pdata, int offset,const header_t *h,unsigned char* pbuffer)
{
	int r;
	unsigned int src_len, dst_len;
	unsigned int c_adler32 = ADLER32_INIT_VALUE, d_adler32 = ADLER32_INIT_VALUE;
	unsigned int c_crc32 = CRC32_INIT_VALUE, d_crc32 = CRC32_INIT_VALUE;
	unsigned int ok = 0;
	mblock_t * const block = &blocks[1];
	unsigned char* b1;
	unsigned char* const b2 = block->mb_mem;
	unsigned int in_processed = 0;
	unsigned int out_processed = 0;
	unsigned char* p = pdata+offset;
	unsigned char* dst = pbuffer;

	for (;;)
	{
		/* read uncompressed block size */
		dst_len = get_be32(p);p+=4;

		/* exit if last block */
		if (dst_len == 0)
			break;

		/* error if split file */
		if (dst_len == 0xffffffffUL)
		{
			/* should not happen - not yet implemented */
			printf("this file is a split file\n");
			ok = 0; break;
		}

		if (dst_len > MAX_BLOCK_SIZE)
		{
			printf("file corrupted\n");
			ok = 0; break;
		}

		/* read compressed block size */
		src_len =get_be32(p);p+=4;
		if (src_len <= 0 || src_len > dst_len || dst_len > BLOCK_SIZE || dst_len > block_size)
		{
			printf("file corrupted\n");
			ok = 0; break;
		}

		/* read checksum of uncompressed block */
		if (h->flags & F_ADLER32_D)
		{
			d_adler32 = get_be32(p);p+=4;
		}
		if (h->flags & F_CRC32_D)
		{
			d_crc32 = get_be32(p);p+=4;
		}

		/* read checksum of compressed block */
		if (h->flags & F_ADLER32_C)
		{
			if (src_len < dst_len)
			{
				c_adler32 = get_be32(p);p+=4;
			}
			else
			{
				c_adler32 = d_adler32;
			}
		}
		if (h->flags & F_CRC32_C)
		{
			if (src_len < dst_len)
			{
				c_crc32 = get_be32(p);p+=4;
			}
			else
			{
				c_crc32 = d_crc32;
			}
		}

		/* read the block */
		b1 = block->mb_mem + block->mb_size - src_len;
		memcpy(b1,p, src_len);p+=src_len;
		in_processed += src_len;

		/* verify checksum of compressed block */
		if ( (h->flags & F_ADLER32_C))
		{
			unsigned int c;
			c = lzo_adler32(ADLER32_INIT_VALUE,b1,src_len);
			if (c != c_adler32)
			{
				printf("Checksum error ( file corrupted)\n");
				ok = 0; break;
			}
		}
		if ((h->flags & F_CRC32_C))
		{
			unsigned int c;
			c = lzo_crc32(CRC32_INIT_VALUE,b1,src_len);
			if (c != c_crc32)
			{
				printf("Checksum error (file corrupted)\n");
				ok = 0; break;
			}
		}

		if (src_len < dst_len)
		{
			unsigned int d = dst_len;

			r = lzo1x_decompress_safe(b1,src_len,b2,&d);

			if (r != LZO_E_OK || dst_len != d )
			{
				printf("file corrupted\n");
				ok = 0; break;
			}
			memcpy(dst,b2, d);
			dst += d;
			ok += d;
		}
	}

	return ok;
}