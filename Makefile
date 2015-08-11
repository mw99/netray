# netray version
VERSION = 1.0

# files
SRC = netray.c
OBJ = ${SRC:.c=.o}

# targets
TARGET = netray

# paths
PREFIX = /usr

# flags
CFLAGS = -DVERSION=\"${VERSION}\" -DTARGET=\"${TARGET}\" -std=c99 -O2 -Wall -Winline -Werror -Wextra -Wno-unused

# compiler
# CC = gcc

# distribution files
DISTFILES = Makefile README.md LICENSE ${SRC} ${TARGET}

############################################################################################
############################################################################################

all: ${TARGET}

options:
	@echo ${TARGET} build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "CC       = ${CC}"

${TARGET}: ${SRC}
	${CC} -o ${TARGET} ${CFLAGS} $<

clean:
	@echo clean up
	@rm -f ${OBJ} ${TARGET}

dist: clean
	@echo creating dist tarball
	mkdir -p ${TARGET}-${VERSION}
	cp -R ${DISTFILES} ${TARGET}-${VERSION}
	tar -cvzf ${TARGET}-${VERSION}.tgz ${TARGET}-${VERSION}
	rm -rf ${TARGET}-${VERSION}

install: all
	@echo installing ${TARGET} to ${DESTDIR}${PREFIX}/lib
	@mkdir -p ${DESTDIR}${PREFIX}/bin
	@cp -f ${TARGET} ${DESTDIR}${PREFIX}/bin

uninstall:
	@echo removing ${TARGET} from ${DESTDIR}${PREFIX}/lib
	@rm -f ${DESTDIR}${PREFIX}/bin/${TARGET}

.PHONY: all options clean dist install uninstall
