#ifndef __SERVER_H__
#define __SERVER_H__

#include <stdint.h>

enum {
	INO_ROOT		= 10,
	INO_FIRST		= INO_ROOT,
	INO_RESERVED_LAST	= 999,
};

struct client {
	uint32_t	current_fh;
};

#endif /* __SERVER_H__ */
