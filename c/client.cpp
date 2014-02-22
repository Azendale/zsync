
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

/* zsync command-line client program */

#include <vector>
#include <string>

#include "zsglobal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <utime.h>

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

// Let C++ compiler know these are C functions, and therefore will not have name mangled names
extern "C" {
#include "libzsync/zsync.h"

#include "http.h"
#include "url.h"
#include "progress.h"
}

class ZsyncClient
{
public:
/* read_seed_file(zsync, filename_str)
 * Reads the given file (decompressing it if appropriate) and applies the rsync
 * checksum algorithm to it, so any data that is contained in the target file
 * is written to the in-progress target. So use this function to supply local
 * source files which are believed to have data in common with the target.
 */
	void read_seed_file(const char *fname);
	
/* zs = read_zsync_control_file(location_str, filename)
 * Reads a zsync control file from either a URL or filename specified in
 * location_str. This is treated as a URL if no local file exists of that name
 * and it starts with a URL scheme ; only http URLs are supported.
 * Second parameter is a filename in which to locally save the content of the
 * .zsync _if it is retrieved from a URL_; can be NULL in which case no local
 * copy is made.
 */
	void read_zsync_control_file(const char *p, const char *fn);
/* str = get_filename_prefix(path_str)
 * Returns a (malloced) string of the alphanumeric leading segment of the
 * filename in the given file path.
 */
	char *get_filename_prefix(const char *p);
/* filename_str = get_filename(zs, source_filename_str)
 * Returns a (malloced string with a) suitable filename for a zsync download,
 * using the given zsync state and source filename strings as hints. */
	std::string get_filename(const char *source_name);
/* prog = calc_zsync_progress(zs)
 * Returns the progress ratio 0..1 (none...done) for the given zsync_state */
	float calc_zsync_progress();
/* fetch_remaining_blocks_http(zs, url, type)
 * For the given zsync_state, using the given URL (which is a copy of the
 * actual content of the target file is type == 0, or a compressed copy of it
 * if type == 1), retrieve the parts of the target that are currently missing. 
 * Returns true if this URL was useful, false if we crashed and burned.
 */
	int fetch_remaining_blocks_http(const char *url, int type);
/* fetch_remaining_blocks(zs)
 * Using the URLs in the supplied zsync state, downloads data to complete the
 * target file. 
 */
	int fetch_remaining_blocks();

	struct zsync_state;

private:
};



/* FILE* f = open_zcat_pipe(file_str)
 * Returns a (popen) filehandle which when read returns the un-gzipped content
 * of the given file. Or NULL on error; or the filehandle may fail to read. It
 * is up to the caller to call pclose() on the handle and check the return
 * value of that.
 */
FILE* open_zcat_pipe(const char* fname)
{
    /* Get buffer to build command line */
    char *cmd = (char *) malloc(6 + strlen(fname) * 2);
    if (!cmd)
        return NULL;

    strcpy(cmd, "zcat ");
    {   /* Add filename to commandline, escaping any characters that the shell
         *might consider special. */
        int i, j;

        for (i = 0, j = 5; fname[i]; i++) {
            if (!isalnum(fname[i]))
                cmd[j++] = '\\';
            cmd[j++] = fname[i];
        }
        cmd[j] = 0;
    }

    if (!no_progress)
        fprintf(stderr, "reading seed %s: ", cmd);
    {   /* Finally, open the subshell for reading, and return the handle */
        FILE* f = popen(cmd, "r");
        free(cmd);
        return f;
    }
}

// TODO: Make part of ZsyncClient class
/* read_seed_file(zsync, filename_str)
 * Reads the given file (decompressing it if appropriate) and applies the rsync
 * checksum algorithm to it, so any data that is contained in the target file
 * is written to the in-progress target. So use this function to supply local
 * source files which are believed to have data in common with the target.
 */
void ZsyncClient::read_seed_file(const char *fname) {
    /* If we should decompress this file */
    if (zsync_hint_decompress(&(this->zsync_state)) && strlen(fname) > 3  && !strcmp(fname + strlen(fname) - 3, ".gz")) {
        /* Open for reading */
        FILE *f = open_zcat_pipe(fname);
        if (!f) {
            perror("popen");
            fprintf(stderr, "not using seed file %s\n", fname);
        }
        else {

            /* Give the contents to libzsync to read and find any useful
             * content */
            zsync_submit_source_file(&zsync_state, f, !no_progress);

            /* Close and check for errors */
            if (pclose(f) != 0) {
                perror("close");
            }
        }
    }
    else {
        /* Simple uncompressed file - open it */
        FILE *f = fopen(fname, "r");
        if (!f) {
            perror("open");
            fprintf(stderr, "not using seed file %s\n", fname);
        }
        else {

            /* Give the contents to libzsync to read, to find any content that
             * is part of the target file. */
            if (!no_progress)
                fprintf(stderr, "reading seed file %s: ", fname);
            zsync_submit_source_file(zsync_state, f, !no_progress);

            /* And close */
            if (fclose(f) != 0) {
                perror("close");
            }
        }
    }

    {   /* And print how far we've progressed towards the target file */
        long long done, total;

        zsync_progress(zsync_state, &done, &total);
        if (!no_progress)
            fprintf(stderr, "\rRead %s. Target %02.1f%% complete.      \n",
                    fname, (100.0f * done) / total);
    }
}

long long http_down;

// TODO: Make part of ZsyncClient Class
/* zs = read_zsync_control_file(location_str, filename)
 * Reads a zsync control file from either a URL or filename specified in
 * location_str. This is treated as a URL if no local file exists of that name
 * and it starts with a URL scheme ; only http URLs are supported.
 * Second parameter is a filename in which to locally save the content of the
 * .zsync _if it is retrieved from a URL_; can be NULL in which case no local
 * copy is made.
 */
void ZsyncClient::read_zsync_control_file(const char *p, const char *fn) {
    FILE *f;
    char *lastpath = NULL;

    /* Try opening as a local path */
    f = fopen(p, "r");
    if (!f) {
        /* No such local file - if not a URL either, report error */
        if (!is_url_absolute(p)) {
            perror(p);
            exit(2);
        }

        /* Try URL fetch */
        f = http_get(p, &lastpath, fn);
        if (!f) {
            fprintf(stderr, "could not read control file from URL %s\n", p);
            exit(3);
        }
        referer = lastpath;
    }

    // TODO 2014-02-22
    /* Read the .zsync */
    if ((*zsync_state = zsync_begin(f)) == NULL) {
        exit(1);
    }

    /* And close it */
    if (fclose(f) != 0) {
        perror("fclose");
        exit(2);
    }
}

/* str = get_filename_prefix(path_str)
 * Returns a (malloced) string of the alphanumeric leading segment of the
 * filename in the given file path.
 */
char *get_filename_prefix(const char *p) {
    // Make our own copy of the string so we can edit it without destroying the original
    char *s = strdup(p);
    
    // Find the last slash in the path and point t to it
    char *t = strrchr(s, '/');
    
    // u will point at the first non alphanumeric character, which will probably be the dot before the extention
    char *u;

    // If the pointer we got back from strrchr was not null, then ...
    if (t)
    {
        // ...change the / in that position to 0, and then increment the pointer to the cstring after it...
        *t++ = 0;
    }
    else // ...otherwise, ...
    {
        // ... make t point at the start of our duplicate of the string.
        t = s;
    }
    
    // Start u out at the start of the t string, but then...
    u = t;
    
    // ... fast forward u until it no longer points at a alphanumeric character.
    while (isalnum(*u)) {
        u++;
    }
    
    // Then set that first non-alphanumeric character to 0, terminating the string t.
    *u = 0;

    
    // If t points at a non-empty cstring...
    if (*t > 0)
    {
        //... make a copy of it to return so that it is safe to delete our working copy of the string, ...
        t = strdup(t);
	}
    else // ... otherwise, ...
    {
        // make t a null pointer to return.
        t = NULL;
    }
    // (free our working copy)
    free(s);
    
    // And, finally return t.
    return t;
}

// TODO: Include in ZsyncClient class
/* filename_str = get_filename(zs, source_filename_str)
 * Returns a (malloced string with a) suitable filename for a zsync download,
 * using the given zsync state and source filename strings as hints. */
std::string get_filename(const char *source_name) {
    std::string p = zsync_filename(&zsync_state);
    std::string filename;

    if (!p.empty()) {
        if (p.find('/') != std::string::npos) {
            fprintf(stderr,
                    "Rejected filename specified in %s, contained path component.\n",
                    source_name);
        }
        else {
            std::string t = get_filename_prefix(source_name);

            if (!t.empty() && t != p)
            {
                filename = p;
            }

            if (!t.empty() && filename.empty()) {
                fprintf(stderr,
                        "Rejected filename specified in %s - prefix %s differed from filename %s.\n",
                        source_name, t.c_str(), p.c_str());
            }
        }
    }
    if (filename.empty()) {
        filename = get_filename_prefix(source_name);
        if (filename.empty())
            filename = "zsync-download";
    }
    return filename;
}


// TODO: include in ZsyncClient class
/* prog = calc_zsync_progress(zs)
 * Returns the progress ratio 0..1 (none...done) for the given zsync_state */
float ZsyncClient::calc_zsync_progress() {
    long long zgot, ztot;

    zsync_progress(&zsync_state, &zgot, &ztot);
    return (100.0f * zgot / ztot);
}


// TODO: Include in ZsyncClient class
/* fetch_remaining_blocks_http(zs, url, type)
 * For the given zsync_state, using the given URL (which is a copy of the
 * actual content of the target file is type == 0, or a compressed copy of it
 * if type == 1), retrieve the parts of the target that are currently missing. 
 * Returns true if this URL was useful, false if we crashed and burned.
 */
#define BUFFERSIZE 8192

int ZsyncClient::fetch_remaining_blocks_http(const char *url, int type) {
    int ret = 0;
    struct range_fetch *rf;
    unsigned char *buf;
    struct zsync_receiver *zr;

    /* URL might be relative - we need an absolute URL to do a fetch */
    char *u = make_url_absolute(referer, url);
    if (!u) {
        fprintf(stderr,
                "URL '%s' from the .zsync file is relative, but I don't know the referer URL (you probably downloaded the .zsync separately and gave it to me as a file). I need to know the referring URL (the URL of the .zsync) in order to locate the download. You can specify this with -u (or edit the URL line(s) in the .zsync file you have).\n",
                url);
        return -1;
    }

    /* Start a range fetch and a zsync receiver */
    rf = range_fetch_start(u);
    if (!rf) {
        free(u);
        return -1;
    }
    zr = zsync_begin_receive(&zsync_state, type);
    if (!zr) {
        range_fetch_end(rf);
        free(u);
        return -1;
    }

    if (!no_progress)
        fprintf(stderr, "downloading from %s:", u);

    /* Create a read buffer */
    buf = (unsigned char *)malloc(BUFFERSIZE);
    if (!buf) {
		// TODO: needs to be replaced with a call to the destructor for zr
        zsync_end_receive(zr);
        range_fetch_end(rf);
        free(u);
        return -1;
    }

    {   /* Get a set of byte ranges that we need to complete the target */
        int nrange;
        off_t *zbyterange = zsync_needed_byte_ranges(&zsync_state, &nrange, type);
        if (!zbyterange)
            return 1;
        if (nrange == 0)
            return 0;

        /* And give that to the range fetcher */
        range_fetch_addranges(rf, zbyterange, nrange);
        free(zbyterange);
    }

    {
        int len;
        off_t zoffset;
        struct progress p = { 0, 0, 0, 0 };

        /* Set up progress display to run during the fetch */
        if (!no_progress) {
            fputc('\n', stderr);
            do_progress(&p, calc_zsync_progress(zsync_state), range_fetch_bytes_down(rf));
        }

        /* Loop while we're receiving data, until we're done or there is an error */
        while (!ret
               && (len = get_range_block(rf, &zoffset, buf, BUFFERSIZE)) > 0) {
            /* Pass received data to the zsync receiver, which writes it to the
             * appropriate location in the target file */
            if (zsync_receive_data(zr, buf, zoffset, len) != 0)
                ret = 1;

            /* Maintain progress display */
            if (!no_progress)
                do_progress(&p, calc_zsync_progress(zsync_state),
                            range_fetch_bytes_down(rf));

            // Needed in case next call returns len=0 and we need to signal where the EOF was.
            zoffset += len;     
        }

        /* If error, we need to flag that to our caller */
        if (len < 0)
            ret = -1;
        else    /* Else, let the zsync receiver know that we're at EOF; there
                 *could be data in its buffer that it can use or needs to process */
            zsync_receive_data(zr, NULL, zoffset, 0);

        if (!no_progress)
            end_progress(&p, zsync_status(z) >= 2 ? 2 : len == 0 ? 1 : 0);
    }

    /* Clean up */
    free(buf);
    http_down += range_fetch_bytes_down(rf);
    zsync_end_receive(zr);
    range_fetch_end(rf);
    free(u);
    return ret;
}

// TODO: Include in ZsyncClient class
/* fetch_remaining_blocks(zs)
 * Using the URLs in the supplied zsync state, downloads data to complete the
 * target file. 
 */
int fetch_remaining_blocks() {
    int n, utype;
    const char *const *url = zsync_get_urls(&zsync_state, &n, &utype);
    int *status;        /* keep status for each URL - 0 means no error */
    int ok_urls = n;

    if (!url) {
        fprintf(stderr, "no URLs available from zsync?");
        return 1;
    }
    status = (int *)calloc(n, sizeof *status);

    /* Keep going until we're done or have no useful URLs left */
    while (zsync_status(&zsync_state) < 2 && ok_urls) {
        /* Still need data; pick a URL to use. */
        int thisTry = rand() % n;

        if (!status[thisTry]) {
            const char *tryurl = url[thisTry];

            /* Try fetching data from this URL */
            int rc = fetch_remaining_blocks_http(zsync_state, tryurl, utype);
            if (rc != 0) {
                fprintf(stderr, "failed to retrieve from %s\n", tryurl);
                status[thisTry] = 1;
                ok_urls--;
            }
        }
    }
    free(status);
    return 0;
}

int set_mtime(std::string filename, time_t mtime) {
    struct stat s;
    struct utimbuf u;

    /* Get the access time, which I don't want to modify. */
    if (stat(filename.c_str(), &s) != 0) {
        perror("stat");
        return -1;
    }
    
    /* Set the modification time. */
    u.actime = s.st_atime;
    u.modtime = mtime;
    if (utime(filename.c_str(), &u) != 0) {
        perror("utime");
        return -1;
    }
    return 0;
}

/****************************************************************************
 *
 * Main program */
int main(int argc, char **argv) {
    struct zsync_state *zs;
    std::string temp_file;
    // "List" (vector, really) of strings, one each per seed file name.
    std::vector<std::string> seedfiles;
    std::string filename;
    long long local_used;
    std::string zfname;
    time_t mtime;

    srand(getpid());
    {   /* Option parsing */
        int opt;

        while ((opt = getopt(argc, argv, "A:k:o:i:Vsqu:")) != -1) {
            switch (opt) {
            case 'A':           /* Authentication options for remote server */
                {               /* Scan string as hostname=username:password */
                    char *p = strdup(optarg);
                    char *q = strchr(p, '=');
                    char *r = q ? strchr(q, ':') : NULL;

                    if (!q || !r) {
                        fprintf(stderr,
                                "-A takes hostname=username:password\n");
                        exit(1);
                    }
                    else {
                        *q++ = *r++ = 0;
                        add_auth(p, q, r);
                    }
                }
                break;
            case 'k':
                zfname = optarg;
                break;
            case 'o':
                filename = optarg;
                break;
            case 'i':
                seedfiles.push_back(std::string(optarg));
                break;
            case 'V':
                printf(PACKAGE " v" VERSION " (compiled " __DATE__ " " __TIME__
                       ")\n" "By Colin Phipps <cph@moria.org.uk>\n"
                       "Published under the Artistic License v2, see the COPYING file for details.\n");
                exit(0);
            case 's':
            case 'q':
                no_progress = 1;
                break;
            case 'u':
                referer = strdup(optarg);
                break;
            }
        }
    }
    

    /* Last and only non-option parameter must be the path/URL of the .zsync */
    if (optind == argc) {
        fprintf(stderr,
                "No .zsync file specified.\nUsage: zsync http://example.com/some/filename.zsync\n");
        exit(3);
    }
    else if (optind < argc - 1) {
        fprintf(stderr,
                "Usage: zsync http://example.com/some/filename.zsync\n");
        exit(3);
    }

    /* No progress display except on terminal */
    if (!isatty(0))
        no_progress = 1;
    {   /* Get proxy setting from the environment */
        char *pr = getenv("http_proxy");

        if (pr != NULL)
            set_proxy_from_string(pr);
    }

    /* STEP 1: Read the zsync control file */
    if ((zs = read_zsync_control_file(argv[optind], zfname.c_str())) == NULL) {
        exit(1);
    }

    /* Get eventual filename for output, and filename to write to while working */
    if (filename.empty())
        filename = get_filename(zs, argv[optind]);
    // filename is a std::string, so it will overload the + operator
    temp_file = filename + ".part";
    
    {   /* STEP 2: read available local data and fill in what we know in the
         *target file */
        size_t i;

        /* If the target file already exists, we're probably updating that file
         * - so it's a seed file */
        // cstring for the access function until I know what it is and if it will take std::string
        if (!access(filename.c_str(), R_OK)) {
            seedfiles.push_back(filename);
        }
        /* If the .part file exists, it's probably an interrupted earlier
         * effort; a normal HTTP client would 'resume' from where it got to,
         * but zsync can't (because we don't know this data corresponds to the
         * current version on the remote) and doesn't need to, because we can
         * treat it like any other local source of data. Use it now. */
        // cstring for the access function until I know what it is and if it will take std::string
        
        if (!access(temp_file.c_str(), R_OK)) {
            seedfiles.push_back(temp_file);
        }


        /* Try any seed files supplied by the command line */
        for (i = 0; i < seedfiles.size(); i++) {
            int dup = 0, j;

            /* And stop reading seed files once the target is complete. */
            if (zsync_status(zs) >= 2) break;

            /* Skip dups automatically, to save the person running the program
             * having to worry about this stuff. */
            // Look through all files processed so far, and see if this one is a
            // duplicate of them. Since we are using std::string, we can just use
            // the == operator to compare.
            for (j = 0; j < i; j++) {
                if (seedfiles[i] == seedfiles[j]) {
                    dup = 1;
                }
            }

            /* And now, if not a duplicate, read it */
            if (!dup) {
                read_seed_file(zs, seedfiles[i].c_str());
            }
        }
        
        /* Show how far that got us */
        zsync_progress(zs, &local_used, NULL);

        /* People that don't understand zsync might use it wrongly and end up
         * downloading everything. Although not essential, let's hint to them
         * that they probably messed up. */
        if (!local_used) {
            if (!no_progress)
                fputs
                    ("No relevent local data found - I will be downloading the whole file. If that's not what you want, CTRL-C out. You should specify the local file is the old version of the file to download with -i (you might have to decompress it with gzip -d first). Or perhaps you just have no data that helps download the file\n",
                     stderr);
        }
    }

    /* libzsync has been writing to a randomely-named temp file so far -
     * because we didn't want to overwrite the .part from previous runs. Now
     * we've read any previous .part, we can replace it with our new
     * in-progress run (which should be a superset of the old .part - unless
     * the content changed, in which case it still contains anything relevant
     * from the old .part). */
    if (zsync_rename_file(zs, temp_file.c_str()) != 0) {
        perror("rename");
        exit(1);
    }

    /* STEP 3: fetch remaining blocks via the URLs from the .zsync */
    if (fetch_remaining_blocks(zs) != 0) {
        fprintf(stderr,
                "failed to retrieve all remaining blocks - no valid download URLs remain. Incomplete transfer left in %s.\n(If this is the download filename with .part appended, zsync will automatically pick this up and reuse the data it has already done if you retry in this dir.)\n",
                temp_file.c_str());
        exit(3);
    }

    {   /* STEP 4: verify download */
        int r;

        if (!no_progress)
            printf("verifying download...");
        r = zsync_complete(zs);
        switch (r) {
        case -1:
            fprintf(stderr, "Aborting, download available in %s\n", temp_file.c_str());
            exit(2);
        case 0:
            if (!no_progress)
                printf("no recognised checksum found\n");
            break;
        case 1:
            if (!no_progress)
                printf("checksum matches OK\n");
            break;
        }
    }
    

    /* Get any mtime that we is suggested to set for the file, and then shut
     * down the zsync_state as we are done on the file transfer. Getting the
     * current name of the file at the same time. */
    mtime = zsync_mtime(zs);
	// TODO: should be changed to zs.zsync_cur_filename() followed by delete zs;.
    temp_file = zsync_end(zs);

    /* STEP 5: Move completed .part file into place as the final target */
    if (!filename.empty()) {
        std::string oldfile_backup;
        int ok = 1;

        oldfile_backup = filename;
        oldfile_backup += ".zs-old";
        
        if (!access(filename.c_str(), F_OK)) {
            /* Backup the old file. */
            /* First, remove any previous backup. We don't care if this fails -
             * the link below will catch any failure */
            unlink(oldfile_backup.c_str());

            /* Try linking the filename to the backup file name, so we will 
               atomically replace the target file in the next step.
               If that fails due to EPERM, it is probably a filesystem that
               doesn't support hard-links - so try just renaming it to the
               backup filename. */
            if (link(filename.c_str(), oldfile_backup.c_str()) != 0
                && (errno != EPERM || rename(filename.c_str(), oldfile_backup.c_str()) != 0)) {
                perror("linkname");
                fprintf(stderr,
                        "Unable to back up old file %s - completed download left in %s\n",
                        filename.c_str(), temp_file.c_str());
                ok = 0;         /* Prevent overwrite of old file below */
            }
        }
        if (ok) {
            /* Rename the file to the desired name */
            if (rename(temp_file.c_str(), filename.c_str()) == 0) {
                /* final, final thing - set the mtime on the file if we have one */
                if (mtime != -1) {
                    set_mtime(filename, mtime);
                }
            }
            else {
                perror("rename");
                fprintf(stderr,
                        "Unable to back up old file %s - completed download left in %s\n",
                        filename.c_str(), temp_file.c_str());
            }
        }
        // std::string that is oldfile_backup will automatically be released when it goes out of scope.
        // Just need to free the dynamic memory we allocated when we made a cstring from it.
    }
    else {
        printf
            ("No filename specified for download - completed download left in %s\n",
             temp_file.c_str());
    }

    /* Final stats and cleanup */
    if (!no_progress)
        printf("used %lld local, fetched %lld\n", local_used, http_down);
    free(referer);
    return 0;
}
