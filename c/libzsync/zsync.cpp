
/*
 *   zsync - client side rsync over http
 *   Copyright (C) 2004,2005,2007,2009 Colin Phipps <cph@moria.org.uk>
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

/* This is the heart of zsync.
 *
 * .zsync file parsing and glue between all the main components of zsync.
 *
 * This file is where the .zsync metadata format is understood and read; it
 * extracts it and creates the corresponding rcksum object to apply the rsync
 * algorithm in constructing the target. It applies the zmap to convert byte
 * ranges between compressed and uncompressed versions of the data as needed,
 * and does decompression on compressed data received. It joins the HTTP code
 * to the rsync algorithm by converting lists of blocks from rcksum into lists
 * of byte ranges at particular URLs to be retrieved by the HTTP code.
 *
 * It also handles:
 * - blocking edge cases (decompressed data not lining up with blocks for rcksum; 
 *   last block of the file only containing partial data)
 * - recompression of the compressed data at the end of the transfer;
 * - checksum verification of the entire output.
 */
#include "zsglobal.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <arpa/inet.h>

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#include "zlib/zlib.h"

#include "librcksum/rcksum.h"
#include "zsync.h"
#include "sha1.h"
#include "zmap.h"

#include <stdexcept>

time_t parse_822(const char* ts);

/* Probably we really want a table of compression methods here. But I've only
 * implemented SHA1 so this is it for now. */
const char ckmeth_sha1[] = { "SHA-1" };

/* List of options strings for gzip(1) allowed in the .zsync. This is 
 * security against someone specifying arbitrary commands. */
static const char* const gzip_safe_option[] = {
    "--best",
    "",
    "--rsync",
    "--rsync --best",
    "--best --no-name",
    "--no-name",
    "--rsync --no-name",
    "--rsync --best --no-name"
};
const int gzip_safe_options = sizeof(gzip_safe_option)/sizeof *gzip_safe_option;

/****************************************************************************
 *
 * zsync_state methods, class defined in zsync.h
 * This holds a single target file's details, and holds the state of the
 * in-progress local copy of that target that we are constructing (via a
 * contained rcksum_state object)
 *
 * Also holds all the other misc data from the .zsync file.
 */


/* char*[] = append_ptrlist(&num, &char[], "to add")
 * Crude data structure to store an ordered list of strings. This appends one
 * entry to the list. */
// TODO: should be replaced by std::vector
static char **append_ptrlist(int *n, char **p, char *a) {
    if (!a)
        return p;
    p = (char ** )realloc(p, (*n + 1) * sizeof *p);
    if (!p) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    p[*n] = a;
    (*n)++;
    return p;
}

/* Constructor */
ZsyncState::ZsyncState(FILE * f) {
    /* Defaults for the checksum bytes and sequential matches properties of the
     * rcksum_state. These are the defaults from versions of zsync before these
     * were variable. */
    int checksum_bytes = 16, rsum_bytes = 4, seq_matches = 1;

    /* Field names that we can ignore if present and not
     * understood. This allows new headers to be added without breaking
     * backwards compatibility, and conversely to add headers that do break
     * backwards compat and have old clients give meaningful errors. */
    char *safelines = NULL;

    /* Allocate memory for the object, initailizing to 0 */
    //struct zsync_state *zs = (zsync_state*)calloc(sizeof *zs, 1);
	// Commented because it shouldn't be nessesary in a class setup
	
    // mtime is a data member of the class
    mtime = -1;

    for (;;) {
        char buf[1024];
        char *p = NULL;
        int l;

        if (fgets(buf, sizeof(buf), f) != NULL) {
            if (buf[0] == '\n')
                break;
            l = strlen(buf) - 1;
            while (l >= 0
                   && (buf[l] == '\n' || buf[l] == '\r' || buf[l] == ' '))
                buf[l--] = 0;

            p = strchr(buf, ':');
        }
        if (p && *(p + 1) == ' ') {
            *p++ = 0;
            p++;
            if (!strcmp(buf, "zsync")) {
                if (!strcmp(p, "0.0.4")) {
                    fprintf(stderr, "This version of zsync is not compatible with zsync 0.0.4 streams.\n");
					throw std::domain_error("zsync");
                }
            }
            else if (!strcmp(buf, "Min-Version")) {
                if (strcmp(p, VERSION) > 0) {
                    fprintf(stderr,
                            "control file indicates that zsync-%s or better is required\n",
                            p);
					throw std::domain_error("Min-Version");
                }
            }
            else if (!strcmp(buf, "Length")) {
                filelen = atoll(p);
            }
            else if (!strcmp(buf, "Filename")) {
                filename = strdup(p);
            }
            else if (!strcmp(buf, "Z-Filename")) {
                zfilename = strdup(p);
            }
            else if (!strcmp(buf, "URL")) {
				// nurl, url members of the class
                url = (char **)append_ptrlist(&(nurl), url, strdup(p));
            }
            else if (!strcmp(buf, "Z-URL")) {
				//nzurl, zurl members of the class
                zurl = (char **)append_ptrlist(&(nzurl), zurl, strdup(p));
            }
            else if (!strcmp(buf, "Blocksize")) {
				// blocksize is a data member of ZsyncState
                blocksize = atol(p);
                if (blocksize < 0 || (blocksize & (blocksize - 1))) {
                    fprintf(stderr, "nonsensical blocksize %ld\n", blocksize);
                    throw std::invalid_argument("Blocksize");
                }
            }
            else if (!strcmp(buf, "Hash-Lengths")) {
                if (sscanf
                    (p, "%d,%d,%d", &seq_matches, &rsum_bytes,
                     &checksum_bytes) != 3 || rsum_bytes < 1 || rsum_bytes > 4
                    || checksum_bytes < 3 || checksum_bytes > 16
                    || seq_matches > 2 || seq_matches < 1) {
                    fprintf(stderr, "nonsensical hash lengths line %s\n", p);
                    throw std::invalid_argument("Hash-Lengths");
                }
            }
            // blocks is a ZsyncState data member
            else if (blocks && !strcmp(buf, "Z-Map2")) {
                int nzblocks;
                struct gzblock *zblock;

                nzblocks = atoi(p);
                if (nzblocks < 0) {
                    fprintf(stderr, "bad Z-Map line\n");
					throw std::invalid_argument("Z-Map");
                }

                zblock = (gzblock *)malloc(nzblocks * sizeof *zblock);
                if (zblock) {
                    if (fread(zblock, sizeof *zblock, nzblocks, f) < nzblocks) {
                        fprintf(stderr, "premature EOF after Z-Map\n");
					throw std::length_error("Z-Map");
                    }

                    // zmap is a data member of the class
                    zmap = zmap_make(zblock, nzblocks);
                    free(zblock);
                }
            }
            else if (!strcmp(buf, ckmeth_sha1)) {
                if (strlen(p) != SHA1_DIGEST_LENGTH * 2) {
                    fprintf(stderr, "SHA-1 digest from control file is wrong length.\n");
                }
                else {
					// Next two items are data members from the class
                    checksum = strdup(p);
                    checksum_method = ckmeth_sha1;
                }
            }
            else if (!strcmp(buf, "Safe")) {
                safelines = strdup(p);
            }
            else if (!strcmp(buf, "Recompress")) {
				// gzhead is a data member of the class
                gzhead = strdup(p);
                if (gzhead) {
                    int i;
                    char *q = strchr(gzhead, ' ');
                    if (!q)
                        q = gzhead + strlen(gzhead);

                    if (*q)
                        *q++ = 0;
                    /* Whitelist for safe options for gzip command line */
                    for (i = 0; i < gzip_safe_options; i++)
                        if (!strcmp(q, gzip_safe_option[i])) {
							// gzopts is a data member of the class
                            gzopts = strdup(q);
                            break;
                        }
                    if( !gzopts ) {
                        fprintf(stderr, "bad recompress options, rejected\n");
                        free(gzhead);
                    }
                }
            }
            else if (!strcmp(buf, "MTime")) {
				// mtime is a class data member
                mtime = parse_822(p);
            }
            else if (!safelines || !strstr(safelines, buf)) {
                fprintf(stderr,
                        "unrecognised tag %s - you need a newer version of zsync.\n",
                        buf);
					throw std::invalid_argument("MTime");
            }
            // filelen, blocksize, blocks all data members of the class
            if (filelen && blocksize)
                blocks = (filelen + blocksize - 1) / blocksize;
        }
        else {
            fprintf(stderr, "Bad line - not a zsync file? \"%s\"\n", buf);
					throw std::invalid_argument("Unknown");
        }
    }
    if (!filelen || !blocksize) {
        fprintf(stderr, "Not a zsync file (looked for Blocksize and Length lines)\n");
					throw std::invalid_argument("Blocks");
    }
    if (zsync_read_blocksums(f, rsum_bytes, checksum_bytes, seq_matches) != 0) {
					throw std::invalid_argument("Blocksums");
    }
}

/* zsync_read_blocksums(self, FILE*, rsum_bytes, checksum_bytes, seq_matches)
 * Called during construction only, this creates the rcksum_state that stores
 * the per-block checksums of the target file and holds the local working copy
 * of the in-progress target. And it populates the per-block checksums from the
 * given file handle, which must be reading from the .zsync at the start of the
 * checksums. 
 * rsum_bytes, checksum_bytes, seq_matches are settings for the checksums,
 * passed through to the rcksum_state. */
int ZsyncState::zsync_read_blocksums(FILE * f,
                                int rsum_bytes, int checksum_bytes,
                                int seq_matches) {
    /* Make the rcksum_state first */
	// rs, blocks, blocksize are members of the class
    if (!(rs = rcksum_init(blocks, blocksize, rsum_bytes,
                               checksum_bytes, seq_matches))) {
        return -1;
    }

    /* Now read in and store the checksums */
    zs_blockid id = 0;
	// blocks is a member of the class
    for (; id < blocks; id++) {
        struct rsum r = { 0, 0 };
        unsigned char checksum[CHECKSUM_SIZE];

        /* Read in */
        if (fread(((char *)&r) + 4 - rsum_bytes, rsum_bytes, 1, f) < 1
            || fread((void *)&checksum, checksum_bytes, 1, f) < 1) {

            /* Error - free the rcksum_state and tell the caller to bail */
            fprintf(stderr, "short read on control file; %s\n",
                    strerror(ferror(f)));
			// rs is a member of the class
            rcksum_end(rs);
            return -1;
        }

        /* Convert to host endian and store */
        r.a = ntohs(r.a);
        r.b = ntohs(r.b);
		// rs is a member of the class
        rcksum_add_target_block(rs, id, r, checksum);
    }
    return 0;
}

/* parse_822(buf[])
 * Parse an RFC822 date string. Returns a time_t, or -1 on failure. 
 * E.g. Tue, 25 Jul 2006 20:02:17 +0000
 */
time_t parse_822(const char* ts) {
    struct tm t;

    if (strptime(ts, "%a, %d %b %Y %H:%M:%S %z", &t) == NULL
        && strptime(ts, "%d %b %Y %H:%M:%S %z", &t) == NULL) {
        return -1;
    }
    return mktime(&t);
}

/* zsync_hint_decompress(self)
 * Returns true if we think we'll be able to download compressed data to get
 * the needed data to complete the target file */
int ZsyncState::zsync_hint_decompress() {
	// nzurl member of the class
    return (nzurl > 0 ? 1 : 0);
}

/* zsync_blocksize(self)
 * Returns the blocksize used by zsync on this target. */
int ZsyncState::zsync_blocksize() {
	// definitely a getter function! :)
    return blocksize;
}

/* char* = zsync_filename(self)
 * Returns the suggested filename to be used for the final result of this
 * zsync.  Malloced string to be freed by the caller. */
char * ZsyncState::zsync_filename() {
	// gzhead, zfilename, filename all members of the class
    return strdup(gzhead && zfilename ? zfilename : filename);
}

/* time_t = zsync_mtime(self)
 * Returns the mtime on the original copy of the target; for the client program
 * to set the mtime of the local file to match, if it so chooses.
 * Or -1 if no mtime specified in the .zsync */
time_t ZsyncState::zsync_mtime() {
	// definitely a getter function! :)
    return mtime;
}

/* zsync_status(self)
 * Returns  0 if we have no data in the target file yet.
 *          1 if we have some but not all
 *          2 or more if we have all.
 * The caller should not rely on exact values 2+; just test >= 2. Values >2 may
 * be used in later versions of libzsync. */
int ZsyncState::zsync_status() {
	// rs is a member of the class
    int todo = rcksum_blocks_todo(rs);

	// blocks is a member of the class
    if (todo == blocks)
	{
        return 0;
	}
    if (todo > 0)
	{
        return 1;
	}
    return 2;                   /* TODO: more? */
}

/* zsync_progress(self, &got, &total)
 * Writes the number of bytes got, and the total to get, into the long longs.
 */
void ZsyncState::zsync_progress(long long *got, long long *total) {

    if (got) {
		// blocks, rs, blocksize are members of the class
        int todo = blocks - rcksum_blocks_todo(rs);
        *got = todo * blocksize;
    }
    if (total)
        *total = blocks * blocksize;
}

/* zsync_get_urls(self, &num, &type)
 * Returns a (pointer to an) array of URLs (returning the number of them in
 * num) that are remote available copies of the target file (according to the
 * .zsync).
 * Note that these URLs could be for encoded versions of the target; a 'type'
 * is returned in *type which tells libzsync in later calls what version of the
 * target is being retrieved. */
const char *const * ZsyncState::zsync_get_urls(int *n, int *t) {
	// zmap, nzurl are members of the class
    if (zmap && nzurl) {
        *n = nzurl;
        *t = 1;
        return zurl;
    }
    else {
        *n = nurl;
        *t = 0;
        return url;
    }
}

/* zsync_needed_byte_ranges(self, &num, type)
 * Returns an array of offsets (2*num of them) for the start and end of num
 * byte ranges in the given type of version of the target (type as returned by
 * a zsync_get_urls call), such that retrieving all these byte ranges would be
 * sufficient to obtain a complete copy of the target file.
 */
off_t * ZsyncState::zsync_needed_byte_ranges(int *num, int type) {
    int nrange;
    off_t *byterange;
    int i;

    /* Request all needed block ranges */
	// rs is a member of the class
    zs_blockid *blrange = rcksum_needed_block_ranges(rs, &nrange, 0, 0x7fffffff);
    if (!blrange)
        return NULL;

    /* Allocate space for byte ranges */
    byterange = (off_t*)malloc(2 * nrange * sizeof *byterange);
    if (!byterange) {
        free(blrange);
        return NULL;
    }

    /* Now convert blocks to bytes.
     * Note: Must cast one operand to off_t as both blocksize and blrange[x]
     * are int's whereas the product must be a file offfset. Needed so we don't
     * truncate file offsets to 32bits on 32bit platforms. */
	// TODO: Could the aformentioned problem be avoided by using off_t's for both in the first place?
    for (i = 0; i < nrange; i++) {
		// blocksize is a member of the class
        byterange[2 * i] = blrange[2 * i] * (off_t)blocksize;
        byterange[2 * i + 1] = blrange[2 * i + 1] * (off_t)blocksize - 1;
    }
    free(blrange);      /* And release the blocks, we're done with them */

    switch (type) {
    case 0:
        *num = nrange;
        return byterange;
    case 1:
        {   /* Convert ranges in the uncompressed data to ranges in the compressed data */
			// zmap is a member of the class
            off_t *zbyterange =
                zmap_to_compressed_ranges(zmap, byterange, nrange, &nrange);

            /* Store the number of compressed ranges and return them, freeing
             * the uncompressed ones now we've used them. */
            if (zbyterange) {
                *num = nrange;
            }
            free(byterange);
            return zbyterange;
        }
    default:
        free(byterange);
        return NULL;
    }
}

/* zsync_submit_source_file(self, FILE*, progress)
 * Read the given stream, applying the rsync rolling checksum algorithm to
 * identify any blocks of data in common with the target file. Blocks found are
 * written to our local copy of the target in progress. Progress reports if
 * progress != 0  */
int ZsyncState::zsync_submit_source_file(FILE * f, int progress) {
	// rs is a member of the class
    return rcksum_submit_source_file(rs, f, progress);
}

char * ZsyncState::zsync_cur_filename() {
    if (!cur_filename)
	{
        cur_filename = rcksum_filename(rs);
	}

    return cur_filename;
}

/* zsync_rename_file(self, filename)
 * Tell libzsync to move the local copy of the target (or under construction
 * target) to the given filename. */
int ZsyncState::zsync_rename_file(const char *f) {
	// zsync_cur_filename is a member of the class
    char *rf = zsync_cur_filename();

    int x = rename(rf, f);

    if (!x) {
        free(rf);
		// cur_filename is a member of the class
        cur_filename = strdup(f);
    }
    else
        perror("rename");

    return x;
}

size_t ZsyncState::get_blocksize()
{
	return blocksize;
}

/* int hexdigit(char)
 * Maps a character to 0..15 as a hex digit (or 0 if not valid hex digit)
 */
static int hexdigit(char c) {
    return (isdigit(c) ? (c - '0') : isupper(c) ? (0xa + (c - 'A')) : islower(c)
            ? (0xa + (c - 'a')) : 0);
}

/* zsync_complete(self)
 * Finish a zsync download. Should be called once all blocks have been
 * retrieved successfully. This returns 0 if the file passes the final
 * whole-file checksum and if any recompression requested by the .zsync file is
 * done.
 * Returns -1 on error (and prints the error to stderr)
 *          0 if successful but no checksum verified
 *          1 if successful including checksum verified
 */
int ZsyncState::zsync_complete() {
    int rc = 0;

    /* We've finished with the rsync algorithm. Take over the local copy from
     * librcksum and free our rcksum state. */
	// rs, zsync_cur_filename are members of the class
    int fh = rcksum_filehandle(rs);
    zsync_cur_filename();
	// Free the rs object.
    rcksum_end(rs);
    rs = NULL;

    /* Truncate the file to the exact length (to remove any trailing NULs from
     * the last block); return to the start of the file ready to verify. */
	// filelen is a member of the class
    if (ftruncate(fh, filelen) != 0) {
        perror("ftruncate");
        rc = -1;
    }
    if (lseek(fh, 0, SEEK_SET) != 0) {
        perror("lseek");
        rc = -1;
    }

    /* Do checksum check */
	// checksum, checksum_method, zsync_sha1 are members of the class
    if (rc == 0 && checksum && !strcmp(checksum_method, ckmeth_sha1)) {
        rc = zsync_sha1(fh);
    }
    close(fh);

    /* Do any requested recompression */
	// gzhead, gzopts, and zsync_recompress are members of the class
    if (rc >= 0 && gzhead && gzopts) {
        if (zsync_recompress() != 0) {
            return -1;
        }
    }
    return rc;
}

/* zsync_sha1(self, filedesc)
 * Given the currently-open-and-at-start-of-file complete local copy of the
 * target, read it and compare the SHA1 checksum with the one from the .zsync.
 * Returns -1 or 1 as per zsync_complete.
 */
int ZsyncState::zsync_sha1(int fh) {
    SHA1_CTX shactx;

    {                           /* Do SHA1 of file contents */
        unsigned char buf[4096];
        int rc;

        SHA1Init(&shactx);
        while (0 < (rc = read(fh, buf, sizeof buf))) {
            SHA1Update(&shactx, buf, rc);
        }
        if (rc < 0) {
            perror("read");
            return -1;
        }
    }

    {                           /* And compare result of the SHA1 with the one from the .zsync */
        unsigned char digest[SHA1_DIGEST_LENGTH];
        int i;

        SHA1Final(digest, &shactx);

        for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
            int j;
			// checksum is a member of the ZsyncState class
            sscanf(&(checksum[2 * i]), "%2x", &j);
            if (j != digest[i]) {
                return -1;
            }
        }
        return 1; /* Checksum verified okay */
    }
}

/* zsync_recompress(self)
 * Called when we have a complete local copy of the uncompressed data, to
 * perform compression requested in the .zsync.
 *
 * Shells out to the standard system gzip(1). Replaces the gzip file header
 * with the one supplied in the .zsync; this means we should get an identical
 * compressed file output to the original compressed file on the source system
 * (to allow the user to verify a checksum on the compressed file, or just
 * because the user is picky and wants their compressed file to match the
 * original).
 *
 * Returns 0 on success, -1 on error (which is reported on stderr). */
int ZsyncState::zsync_recompress() {
    /* Recompression. This is a fugly mess, calling gzip on the temporary file with options
     *  read out of the .zsync, reading its output and replacing the gzip header. Ugh. */
    FILE *g;
    FILE *zout;
    int rc = 0;

    char cmd[1024];
	// gzopts is a member of the class
    snprintf(cmd, sizeof(cmd), "gzip -n %s < ", gzopts);

    {   /* Add input filename, shell-escaped, to the command line */
        int i = 0;
        size_t j = strlen(cmd);
        char c;

		// cur_filename is a member of the class
        while ((c = cur_filename[i++]) != 0 && j < sizeof(cmd) - 2) {
            if (!isalnum(c))
                cmd[j++] = '\\';
            cmd[j++] = c;
        }
        cmd[j] = 0;
    }

    /* Read gzipped version of the data via pipe from gzip; write it to our new
     * output file, except that we replace the gzip header with our own from
     * the .zsync file. */
    g = popen(cmd, "r");
    if (g) {
        char zoname[1024];

		// cur_filename part of the class
        snprintf(zoname, sizeof(zoname), "%s.gz", cur_filename);
        zout = fopen(zoname, "w");

        if (zout) {
			// gzhead part of the class
            char *p = gzhead;
            int skip = 1;

            while (p[0] && p[1]) {
                if (fputc((hexdigit(p[0]) << 4) + hexdigit(p[1]), zout) == EOF) {
                    perror("putc");
                    rc = -1;
                }
                p += 2;
            }
            
            // could breaking from the loop, and setting a flag declared right after this comment
            // and then putting a check of that flag at the leave_it marker get around a goto?
            // (am I missing something?)
            while (!feof(g)) {
                char buf[1024];
                int r;
                const char *p = buf;

                if ((r = fread(buf, 1, sizeof(buf), g)) < 0) {
                    perror("fread");
                    rc = -1;
                    goto leave_it;
                }
                if (skip) {
                    p = skip_zhead(buf);
                    skip = 0;
                }
                if (fwrite(p, 1, r - (p - buf), zout) != r - (p - buf)) {
                    perror("fwrite");
                    rc = -1;
                    goto leave_it;
                }
            }

          leave_it:
            if (fclose(zout) != 0) {
                perror("close");
                rc = -1;
            }
        }
        if (fclose(g) != 0) {
            perror("close");
            rc = -1;
        }

        /* Free our old filename and replace with the new one */
		// TODO: this could be way easier with std::string
        unlink(cur_filename);
        free(cur_filename);
        cur_filename = strdup(zoname);
    }
    else {
        fprintf(stderr, "problem with gzip, unable to compress.\n");
    }
    return rc;
}

/* Destructor */
ZsyncState::~ZsyncState() {
    int i;

    /* Free rcksum object and zmap */
    if (rs)
        rcksum_end(rs);
    if (zmap)
        zmap_free(zmap);

    /* Clear download URLs */
    for (i = 0; i < nurl; i++)
        free(url[i]);
    for (i = 0; i < nzurl; i++)
        free(zurl[i]);

    /* And the rest. */
    free(url);
    free(zurl);
    free(checksum);
    free(filename);
    free(zfilename);
}

/* Next come the methods for accepting data received from the remote copies of
 * the target and incomporating them into the local copy under construction. */

/* zsync_configure_zstream_for_zdata(self, &z_stream_s, zoffset, &outoffset)
 * Rewrites the state in the given zlib stream object to be ready to decompress
 * data from the compressed version of this zsync stream at the given offset in
 * the compressed file. Returns the offset in the uncompressed stream that this
 * corresponds to in the 4th parameter. 
 */
void ZsyncState::zsync_configure_zstream_for_zdata(struct z_stream_s *zstrm,
                                                   long zoffset, long long *poutoffset) {
	// zmap is a data member of the class
    configure_zstream_for_zdata(zmap, zstrm, zoffset, poutoffset);
    {                           /* Load in prev 32k sliding window for backreferences */
        long long pos = *poutoffset;
        int lookback = (pos > 32768) ? 32768 : pos;

        /* Read in 32k of leading uncompressed context - needed because the deflate
         * compression method includes back-references to previously-seen strings. */
        unsigned char wbuf[32768];
		// rs is a class data member
        rcksum_read_known_data(rs, wbuf, pos - lookback, lookback);

        /* Fake an output buffer of 32k filled with data to zlib */
        zstrm->next_out = wbuf + lookback;
        zstrm->avail_out = 0;
        updatewindow(zstrm, lookback);
    }
}

/* zsync_submit_data(self, buf[], offset, blocks)
 * Passes data retrieved from the remote copy of
 * the target file to libzsync, to be written into our local copy. The data is
 * the given number of blocks at the given offset (must be block-aligned), data
 * in buf[].  */
int ZsyncState::zsync_submit_data(const unsigned char *buf, off_t offset,
                                  int blocks) {
	// blocksize data member of the class
    zs_blockid blstart = offset / blocksize;
    zs_blockid blend = blstart + blocks - 1;

	// rs is a class data member
    return rcksum_submit_blocks(rs, buf, blstart, blend);
}

/****************************************************************************
 *
 * ZsyncReceiver methods. Object defined in the zsync.h header.
 * Stores the state for a currently-running download of blocks from a
 * particular URL or version of a file to complete a file using zsync.
 *
 * This is mostly a wrapper for the ZsyncState which keeps various additional
 * state needed per-download: in particular the zlib stream object to
 * decompress the incoming data if this is a URL of a compressed version of the
 * target file.
 */

/* Constructor */
void ZsyncReceiver::zsync_begin_receive(class ZsyncState *zs_in, int url_type) {

    // save the pointer to the ZsyncState we are working on/for
    zs = zs_in;

	// Create a buffer the size of the ZsyncState object's blocksize
    outbuf = new unsigned char [zs->get_blocksize()];

    /* Set up new inflate object */
	// strm is a data member of ZsyncReceiver
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = NULL;
    strm.total_in = 0;

	// Both data members of the class
    url_type = url_type;
    outoffset = 0;
}

ZsyncReceiver::ZsyncReceiver(class ZsyncState *zs_in, int url_type) {

    // save the pointer to the ZsyncState we are working on/for
    zs = zs_in;

	// Create a buffer the size of the ZsyncState object's blocksize
    outbuf = new unsigned char [zs->get_blocksize()];

    /* Set up new inflate object */
	// strm is a data member of ZsyncReceiver
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = NULL;
    strm.total_in = 0;

	// Both data members of the class
    url_type = url_type;
    outoffset = 0;
}


/* zsync_receive_data_uncompressed(self, buf[], offset, buflen)
 * Adds the data in buf (buflen bytes) to this file at the given offset.
 * Returns 0 unless there's an error (e.g. the submitted data doesn't match the
 * expected checksum for the corresponding blocks)
 */
int ZsyncReceiver::zsync_receive_data_uncompressed(const unsigned char *buf,
                                                          off_t offset, size_t len) {
    int ret = 0;
	// _l name used to differentiate from blocksize, which is a data member of ZsyncReceiver
    size_t blocksize_l = zs->get_blocksize();

    if (0 != (offset % blocksize_l)) {
        size_t x = len;

        if (x > blocksize_l - (offset % blocksize_l))
            x = blocksize_l - (offset % blocksize_l);

        if (outoffset == offset) {
            /* Half-way through a block, so let's try and complete it */
            if (len)
                memcpy(outbuf + offset % blocksize_l, buf, x);
            else {
                // Pad with 0s to length.
                memset(outbuf + offset % blocksize_l, 0, len = x =
                       blocksize_l - (offset % blocksize_l));
            }

            if ((x + offset) % blocksize_l == 0)
                if (zs->zsync_submit_data
                    (outbuf, outoffset + x - blocksize_l, 1))
                    ret = 1;
        }
        buf += x;
        len -= x;
        offset += x;
    }

    /* Now we are block-aligned */
    if (len >= blocksize_l) {
        int w = len / blocksize_l;

        if (zs->zsync_submit_data(buf, offset, w))
            ret = 1;

        w *= blocksize_l;
        buf += w;
        len -= w;
        offset += w;

    }
    /* Store incomplete block */
    if (len) {
        memcpy(outbuf, buf, len);
        offset += len;          /* not needed: buf += len; len -= len; */
    }

    outoffset = offset;
    return ret;
}

/* zsync_receive_data_compressed(self, buf[], offset, buflen)
 * Passes data received corresponding to the compressed version of this file at
 * the given offset; data in buf, buflen bytes.
 * Returns 0 unless there's an error (e.g. the submitted data doesn't match the
 * expected checksum for the corresponding blocks)
 */
int ZsyncReceiver::zsync_receive_data_compressed(const unsigned char *buf, off_t offset,
                                                        size_t len) {
    int ret = 0;
    int eoz = 0;
    
    // zs is a data member of the ZsyncReceiver class, that points to the ZsyncState object we are working on/for
	// _l name is to indicate local to this function as the ZsyncReceiver also has something named the same
    size_t blocksize_l = zs->get_blocksize();

    if (len == 0)
        return 0;

    /* Now set up for the downloaded block */
    // TODO: Come back to this, cast just what the compiler suggested, no nessesarily what it should be
    strm.next_in = (Bytef*)buf;
    strm.avail_in = len;

    // TODO: Come back to this, cast just what the compiler suggested, no nessesarily what it should be (long long int * cast)
    if (strm.total_in == 0 || offset != strm.total_in) {
        zs->zsync_configure_zstream_for_zdata(&(strm), offset,
                                          (long long int *)&(outoffset));

        /* On first iteration, we might be reading an incomplete block from zsync's point of view. Limit avail_out so we can stop after doing that and realign with the buffer. */
        strm.avail_out = blocksize_l - (outoffset % blocksize_l);
        strm.next_out = outbuf;
    }
    else {
        if (outoffset == -1) {
            fprintf(stderr,
                    "data didn't align with block boundary in compressed stream\n");
            return 1;
        }
        
        //TODO: come back to this, cast is just what the compiler suggested, not nessesarily what it should be
        strm.next_in = (Bytef*)buf;
        strm.avail_in = len;
    }

    while (strm.avail_in && !eoz) {
        int rc;

        /* Read in up to the next block (in the libzsync sense on the output stream) boundary */

        rc = inflate(&(strm), Z_SYNC_FLUSH);
        switch (rc) {
        case Z_STREAM_END:
            eoz = 1;
        case Z_BUF_ERROR:
        case Z_OK:
            if (strm.avail_out == 0 || eoz) {
                /* If this was at the start of a block, try submitting it */
                if (!(outoffset % blocksize_l)) {
                    int rc;

                    if (strm.avail_out)
                        memset(strm.next_out, 0, strm.avail_out);
                    rc = zs->zsync_submit_data(outbuf,
                                           outoffset, 1);
                    if (!strm.avail_out)
                        ret |= rc;
                    outoffset += blocksize_l;
                }
                else {
                    /* We were reading a block fragment; update outoffset, and we are now block-aligned. */
                    outoffset += (strm.next_out - outbuf);
                }
                strm.avail_out = blocksize_l;
                strm.next_out = outbuf;
            }
            break;
        default:
            fprintf(stderr, "zlib error: %s (%d)\n", strm.msg, rc);
            eoz = 1;
            ret = -1;
            break;
        }
    }
    return ret;
}

/* zsync_receive_data(self, buf[], offset, buflen)
 * Passes data received from the source URL at the given offset; 
 * data is buflen bytes in buf[].
 * Returns 0 unless there's an error (e.g. the submitted data doesn't match the
 * expected checksum for the corresponding blocks)
 */
int ZsyncReceiver::zsync_receive_data(const unsigned char *buf,
                                      off_t offset, size_t len) {
    
    // url_type is a data member of ZsyncReceiver, as is zsync_receive_data_*
    if (url_type == 1) {
        return zsync_receive_data_compressed(buf, offset, len);
    }
    else {
        return zsync_receive_data_uncompressed(buf, offset, len);
    }
}

ZsyncReceiver::~ZsyncReceiver()
{
	// strm is a data member of ZsyncReceiver
    if (strm.total_in > 0) {
        inflateEnd(&(strm));
    }
    // outbuf is a data member of ZsyncReceiver
    delete [] outbuf;
}