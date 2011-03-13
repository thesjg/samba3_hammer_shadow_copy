CC		= gcc
CFLAGS		= -g -O2 -I/usr/pkg/include/krb5 
CPPFLAGS	=  -I/usr/pkg/include/krb5 
LDFLAGS		= 
LDSHFLAGS	= -shared
INSTALLCMD	= /usr/bin/install -c
SAMBA_SOURCE	= /home/sjg/projects/samba/source3
SHLIBEXT	= so
OBJEXT		= o 
FLAGS		=  $(CFLAGS) $(CPPFLAGS) -fPIC \
		-Iinclude -I$(SAMBA_SOURCE)/include \
		-I$(SAMBA_SOURCE)/../popt  \
		-I$(SAMBA_SOURCE)/../lib/replace  \
		-I$(SAMBA_SOURCE)/../lib/talloc  \
		-I$(SAMBA_SOURCE)/../lib/tevent  \
		-I$(SAMBA_SOURCE)/../lib/tdb/include  \
		-I$(SAMBA_SOURCE)/librpc \
		-I$(SAMBA_SOURCE)/../librpc \
		-I$(SAMBA_SOURCE)/../ \
		-I$(SAMBA_SOURCE) -I.


prefix		= /usr/local
libdir		= ${prefix}/lib

VFS_LIBDIR	= $(libdir)/vfs

# Auto target
default: $(patsubst %.c,%.$(SHLIBEXT),$(wildcard *.c))

# Pattern rules

%.$(SHLIBEXT): %.$(OBJEXT)
	@echo "Linking $@"
	@$(CC) $(LDSHFLAGS) $(LDFLAGS) -o $@ $<

%.$(OBJEXT): %.c
	@echo "Compiling $<"
	@$(CC) $(FLAGS) -c $<


install: default
	$(INSTALLCMD) -d $(VFS_LIBDIR)
	$(INSTALLCMD) -m 755 *.$(SHLIBEXT) $(VFS_LIBDIR)

# Misc targets
clean:
	rm -rf .libs
	rm -f core *~ *% *.bak *.o *.$(SHLIBEXT)

distclean: clean
	rm -f config.status config.cache Makefile

