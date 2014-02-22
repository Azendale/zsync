/*
 *   zsync - client side rsync over http
 *   Copyright (C) 2004,2005,2009 Colin Phipps <cph@moria.org.uk>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the Artistic License v2 (see the accompanying 
 *   file COPYING for the full license terms), or, at your option, any later 
 *   version of the same license.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   COPYING file for details.
 */

#ifndef ZSYNC_H
#define ZSYNC_H

#include "zlib/zlib.h"

class ZsyncState
{
public:
/* zsync_begin - load a zsync file and return data structure to use for the rest of the process.
 */
// TODO: this is the constructor
	void zsync_begin(FILE* cf);
/* zsync_hint_decompress - if it returns non-zero, this suggests that 
 *  compressed seed files should be decompressed */
	int zsync_hint_decompress();

/* zsync_filename - return the suggested filename from the .zsync file */
	char* zsync_filename();
	
/* zsync_mtime - return the suggested mtime from the .zsync file */
	time_t zsync_mtime();

/* zsync_rename_file - renames the temporary file used by zsync to the given name.
 * You don't "own" the filename until you zsync_end, but you can use this to give zsync a more 
 * appropriate intermediate filename (in case the user ctrl-c's). 
 * This is purely a hint; zsync could ignore it. Returns 0 if successful. */
	int zsync_rename_file(const char* f);

/* zsync_status - returns the current state:
 * 0 - no relevant local data found yet.
 * 1 - some data present
 * 2+ - all data downloaded (higher values may be added later to indicate completion
 *      of checksumming and file handle states)
 */

	int zsync_status();

/* zsync_progress - returns bytes of the file known so far in *got,
 * and the total (roughly, the file length) in *total */
	void zsync_progress(long long* got, long long* total);

/* zsync_submit_source_file - submit local file data to zsync
 */
	int zsync_submit_source_file(FILE* f, int progress);

/* zsync_get_url - returns a URL from which to get needed data.
 * Returns NULL on failure, or a array of pointers to URLs.
 * Returns the size of the array in *n,
 * and the url type (to pass to needed_byte_ranges & begin_receive)
 * (the URL pointers are still referenced by the library, and are valid only until zsync_end).
 */
	const char * const * zsync_get_urls(int* n, int* t);

/* zsync_needed_byte_ranges - get the byte ranges needed from a URL.
 * Returns the number of ranges in *num, and a malloc'd array (to be freed 
 * by the caller) of 2*(*num) off_t's which are the starts and ends 
 * of byte ranges.
 */

	off_t* zsync_needed_byte_ranges(int* num, int type);

/* zsync_complete - set file length and verify checksum if available
 * Returns -1 for failure, 1 for success, 0 for unable to verify (e.g. no checksum in the .zsync) */
	int zsync_complete();

/* Clean up and free all resources. The pointer is freed by this call.
 * Returns a strdup()d pointer to the name of the file resulting from the process. */
// TODO: sounds like this should be the destructor
	char* zsync_end();

/* zsync_submit_data(self, buf[], offset, blocks)
 * Passes data retrieved from the remote copy of
 * the target file to libzsync, to be written into our local copy. The data is
 * the given number of blocks at the given offset (must be block-aligned), data
 * in buf[].  */
	int zsync_submit_data(const unsigned char *buf, off_t offset, int blocks);
	
/* zsync_configure_zstream_for_zdata(self, &z_stream_s, zoffset, &outoffset)
 * Rewrites the state in the given zlib stream object to be ready to decompress
 * data from the compressed version of this zsync stream at the given offset in
 * the compressed file. Returns the offset in the uncompressed stream that this
 * corresponds to in the 4th parameter. 
 */
	void zsync_configure_zstream_for_zdata(struct z_stream_s *zstrm, long zoffset, long long *poutoffset);

/* zsync_blocksize(self)
 * Returns the blocksize used by zsync on this target. */
	int zsync_blocksize();
	
	char * zsync_cur_filename();/* Returns the current filname */
	
	size_t get_blocksize(); // Returns the blocksize
	
private:
    struct rcksum_state *rs;    /* rsync algorithm state, with block checksums and
                                 * holding the in-progress local version of the target */
    off_t filelen;              /* Length of the target file */
    int blocks;                 /* Number of blocks in the target */
    size_t blocksize;           /* Blocksize */

    /* Checksum of the entire file, and checksum alg */
    char *checksum;
    const char *checksum_method;

    /* URLs to uncompressed versions of the target */
    char **url;
    int nurl;

    /* URLs to compressed versions of the target, and the zmap of that compressed version */
    struct zmap *zmap;
    char **zurl;
    int nzurl;

    char *cur_filename;         /* If we have taken the filename from rcksum, it is here */

    /* Hints for the output file, from the .zsync */
    char *filename;             /* The Filename: header */
    char *zfilename;            /* ditto Z-Filename: */

    char *gzopts;               /* If we're recompressing the download afterwards, these are the options to gzip(1) */
    char *gzhead;               /* And this is the header of the gzip file (for the mtime) */

    time_t mtime;               /* MTime: from the .zsync, or -1 */
	int zsync_read_blocksums(FILE * f, int rsum_bytes, int checksum_bytes, int seq_matches);
	int zsync_sha1(int fh);
	int zsync_recompress();
};


/* And functions for receiving data on the network */
//struct zsync_receiver;
class ZsyncReceiver
{
public:
/* Begin and end receiving from a particular URL.
 * Note that the zsync_receiver stores a reference to the zsync_state, 
 *  and libzsync does not do reference counting, so it is the caller's 
 *  responsibility not to do a zsync_end without doing a zsync_end_receive 
 *  first.
 * The url_type is as in the value returned by zsync_get_url.
 */
	ZsyncReceiver(class ZsyncState *zs_in, int url_type);
	void zsync_begin_receive(class ZsyncState *zs_in, int url_type);

/* Supply data buf of length len received corresponding to offset offset from the URL.
 * Returns 0 for success; if not, you should not submit more data. */
	int zsync_receive_data(const unsigned char* buf, off_t offset, size_t len);
	
// replaced by destructor
//void zsync_end_receive();
	~ZsyncReceiver();           /* Destrutor, now that we dynamically allocate memory */
private:
	ZsyncState * zs;            /* The zsync_state that we are downloading for */
	struct z_stream_s strm;     /* Decompression object */
	int url_type;               /* Compressed or not */
	unsigned char *outbuf;      /* Working buffer to keep incomplete blocks of data */
	off_t outoffset;            /* and the position in that buffer */
	int zsync_receive_data_compressed(const unsigned char *buf, off_t offset, size_t len);
	int zsync_receive_data_uncompressed(const unsigned char *buf, off_t offset, size_t len);
};

// End of ZSYNC_H header gaurd
#endif