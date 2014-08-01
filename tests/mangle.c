/*
  trivial binary file fuzzer by Ilja van Sprundel.
  It's usage is very simple, it takes a filename and headersize
  as input. it will then change approximatly between 0 and 10% of 
  the header with random bytes (biased towards the highest bit set)
 
  obviously you need a bash script or something as a wrapper !

  so far this broke: - libmagic (used file)
                     - preview (osX pdf viewer)
		     - xpdf (hang, not a crash ...)
		     - mach-o loading (osX 10.3.7, seems to be fixed later)
		     - qnx elf loader (panics almost instantly, yikes !)
		     - FreeBSD elf loading 
		     - openoffice
		     - amp
		     - osX image loading (.dmg) 
		     - libbfd (used objdump)
		     - libtiff (used tiff2pdf)
		     - xine (division by 0, took 20 minutes of fuzzing)
		     - OpenBSD elf loading (3.7 on a sparc)
		     - unixware 713 elf loading
		     - DragonFlyBSD elf loading
		     - solaris 10 elf loading 
		     - cistron-radiusd
		     - linux ext2fs (2.4.29) image loading (division by 0)
		     - linux reiserfs (2.4.29) image loading (instant panic !!!)
		     - linux jfs (2.4.29) image loading (long (uninteruptable) loop, 2 oopses)
		     - linux xfs (2.4.29) image loading (instant panic)
		     - windows macromedia flash .swf loading (obviously the windows version of mangle needs a few tweaks to work ...)
		     - Quicktime player 7.0.1 for MacOS X
		     - totem
		     - gnumeric
                     - vlc
                     - mplayer
                     - python bytecode interpreter
                     - realplayer 10.0.6.776 (GOLD)
                     - dvips
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>


#define DEFAULT_HEADER_SIZE 1024
#define DEFAULT_NAME "test2"

int getseed(void) {
	int fd = open("/dev/urandom", O_RDONLY);
	int r;
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	if(read(fd, &r, sizeof(r)) == -1) {
	  close(fd);
	  perror("could not read from /dev/urandom");
	  exit(1);
	}
	close(fd);
	return(r);
}

int main(int argc, char **argv) {
	
	int fd;
	char *p, *name;
	unsigned char c;
	unsigned int count, i, off, hsize;

	if (argc < 2) {
		hsize = DEFAULT_HEADER_SIZE;
		name = DEFAULT_NAME;
	} else if (argc < 3) {
		hsize = DEFAULT_HEADER_SIZE;
		name = argv[1];
	} else {
		hsize = atoi(argv[2]);
		name = argv[1];
	}
	fd = open(name, O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(0);
	}
	p = mmap(0, hsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(0);
	}
	srand(getseed());
	count = (unsigned) rand() % (hsize / 10);
	for (i = 0; i < count; i++) {
		off = rand() % hsize;
		c = rand() % 256;
		/* we want the highest bit set more often, in case of signedness issues */
		if ( (rand() % 2) && c < 128) c |= 0x80;
		p[off] = c;
	}
	close(fd);
	munmap(p, hsize);

	return 0;
}
