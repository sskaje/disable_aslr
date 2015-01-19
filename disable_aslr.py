#!/usr/bin/python

"""
Disable MH_PIE / Remove ASLR for Mach-O binary

Author: sskaje (https://sskaje.me/)

Blog posts:
	https://sskaje.me/2014/05/mach-o-disable-aslr-pie/

"""

import os
import sys
import struct
import shutil

__author__ = 'sskaje'

'''
/Developer/Platforms/iPhoneOS.platform//Developer/SDKs/iPhoneOS7.1.sdk/usr/include/mach-o/loader.h

/*
 * The 32-bit mach header appears at the very beginning of the object file for
 * 32-bit architectures.
 */
struct mach_header {
        uint32_t        magic;          /* mach magic number identifier */
        cpu_type_t      cputype;        /* cpu specifier */
        cpu_subtype_t   cpusubtype;     /* machine specifier */
        uint32_t        filetype;       /* type of file */
        uint32_t        ncmds;          /* number of load commands */
        uint32_t        sizeofcmds;     /* the size of all the load commands */
        uint32_t        flags;          /* flags */
};

/* Constant for the magic field of the mach_header (32-bit architectures) */
#define MH_MAGIC        0xfeedface      /* the mach magic number */
#define MH_CIGAM        0xcefaedfe      /* NXSwapInt(MH_MAGIC) */

/*
 * The 64-bit mach header appears at the very beginning of object files for
 * 64-bit architectures.
 */
struct mach_header_64 {
        uint32_t        magic;          /* mach magic number identifier */
        cpu_type_t      cputype;        /* cpu specifier */
        cpu_subtype_t   cpusubtype;     /* machine specifier */
        uint32_t        filetype;       /* type of file */
        uint32_t        ncmds;          /* number of load commands */
        uint32_t        sizeofcmds;     /* the size of all the load commands */
        uint32_t        flags;          /* flags */
        uint32_t        reserved;       /* reserved */
};

/* Constant for the magic field of the mach_header_64 (64-bit architectures) */
#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */


...


#define MH_OBJECT       0x1             /* relocatable object file */
#define MH_EXECUTE      0x2             /* demand paged executable file */
#define MH_FVMLIB       0x3             /* fixed VM shared library file */
#define MH_CORE         0x4             /* core file */
#define MH_PRELOAD      0x5             /* preloaded executable file */
#define MH_DYLIB        0x6             /* dynamically bound shared library */
#define MH_DYLINKER     0x7             /* dynamic link editor */
#define MH_BUNDLE       0x8             /* dynamically bound bundle file */
#define MH_DYLIB_STUB   0x9             /* shared library stub for static */
                                        /*  linking only, no section contents */
#define MH_DSYM         0xa             /* companion file with only debug */
                                        /*  sections */
#define MH_KEXT_BUNDLE  0xb             /* x86_64 kexts */

/* Constants for the flags field of the mach_header */
#define MH_NOUNDEFS     0x1             /* the object file has no undefined
                                           references */
#define MH_INCRLINK     0x2             /* the object file is the output of an
                                           incremental link against a base file
                                           and can't be link edited again */
#define MH_DYLDLINK     0x4             /* the object file is input for the
                                           dynamic linker and can't be staticly
                                           link edited again */
#define MH_BINDATLOAD   0x8             /* the object file's undefined
                                           references are bound by the dynamic
                                           linker when loaded. */
#define MH_PREBOUND     0x10            /* the file has its dynamic undefined
                                           references prebound. */
#define MH_SPLIT_SEGS   0x20            /* the file has its read-only and
                                           read-write segments split */
#define MH_LAZY_INIT    0x40            /* the shared library init routine is
                                           to be run lazily via catching memory
                                           faults to its writeable segments
                                           (obsolete) */
#define MH_TWOLEVEL     0x80            /* the image is using two-level name
                                           space bindings */
#define MH_FORCE_FLAT   0x100           /* the executable is forcing all images
                                           to use flat name space bindings */
#define MH_NOMULTIDEFS  0x200           /* this umbrella guarantees no multiple
                                           defintions of symbols in its
                                           sub-images so the two-level namespace
                                           hints can always be used. */
#define MH_NOFIXPREBINDING 0x400        /* do not have dyld notify the
                                           prebinding agent about this
                                           executable */
#define MH_PREBINDABLE  0x800           /* the binary is not prebound but can
                                           have its prebinding redone. only used
                                           when MH_PREBOUND is not set. */
#define MH_ALLMODSBOUND 0x1000          /* indicates that this binary binds to
                                           all two-level namespace modules of
                                           its dependent libraries. only used
                                           when MH_PREBINDABLE and MH_TWOLEVEL
                                           are both set. */
#define MH_SUBSECTIONS_VIA_SYMBOLS 0x2000/* safe to divide up the sections into
                                            sub-sections via symbols for dead
                                            code stripping */
#define MH_CANONICAL    0x4000          /* the binary has been canonicalized
                                           via the unprebind operation */
#define MH_WEAK_DEFINES 0x8000          /* the final linked image contains
                                           external weak symbols */
#define MH_BINDS_TO_WEAK 0x10000        /* the final linked image uses
                                           weak symbols */

#define MH_ALLOW_STACK_EXECUTION 0x20000/* When this bit is set, all stacks
                                           in the task will be given stack
                                           execution privilege.  Only used in
                                           MH_EXECUTE filetypes. */
#define MH_ROOT_SAFE 0x40000           /* When this bit is set, the binary
                                          declares it is safe for use in
                                          processes with uid zero */

#define MH_SETUID_SAFE 0x80000         /* When this bit is set, the binary
                                          declares it is safe for use in
                                          processes when issetugid() is true */

#define MH_NO_REEXPORTED_DYLIBS 0x100000 /* When this bit is set on a dylib,
                                          the static linker does not need to
                                          examine dependent dylibs to see
                                          if any are re-exported */
#define MH_PIE 0x200000                 /* When this bit is set, the OS will
                                           load the main executable at a
                                           random address.  Only used in
                                           MH_EXECUTE filetypes. */
#define MH_DEAD_STRIPPABLE_DYLIB 0x400000 /* Only for use on dylibs.  When
                                             linking against a dylib that
                                             has this bit set, the static linker
                                             will automatically not create a
                                             LC_LOAD_DYLIB load command to the
                                             dylib if no symbols are being
                                             referenced from the dylib. */
#define MH_HAS_TLV_DESCRIPTORS 0x800000 /* Contains a section of type
                                            S_THREAD_LOCAL_VARIABLES */

#define MH_NO_HEAP_EXECUTION 0x1000000  /* When this bit is set, the OS will
                                           run the main executable with
                                           a non-executable heap even on
                                           platforms (e.g. i386) that don't
                                           require it. Only used in MH_EXECUTE
                                           filetypes. */




/Developer/Platforms/iPhoneOS.platform//Developer/SDKs/iPhoneOS7.1.sdk/usr/include/mach-o/fat.h


struct fat_header {
        uint32_t        magic;          /* FAT_MAGIC */
        uint32_t        nfat_arch;      /* number of structs that follow */
};

struct fat_arch {
        cpu_type_t      cputype;        /* cpu specifier (int) */
        cpu_subtype_t   cpusubtype;     /* machine specifier (int) */
        uint32_t        offset;         /* file offset to this object file */
        uint32_t        size;           /* size of this object file */
        uint32_t        align;          /* alignment as a power of 2 */
};

'''
FAT_MAGIC = 0xcafebabe          # Mach O Fat Binary

MACH_O_MAGIC_32 = 0xfeedface    # Mach O 32-bit
MACH_O_MAGIC_64 = 0xfeedfacf    # Mach O 64-bit

MAGIC_LENGTH = 4                # 32-bit 
MACH_HEADER_MIN_LENGTH = 24     # 6 32-bit int

FAT_HEADER_LENGTH = 8           # fat_header length, 8 bytes
FAT_ARCH_LENGTH = 20            # fat_arch length, 20 bytes

""" 
cputype and cpusubtype can be found: 
http://www.opensource.apple.com/source/cctools/cctools-862/include/mach/machine.h 
"""
CPU_TYPES = {
    0x00000007: 'X86',
    0x01000007: 'X86_64',
    0x0000000c: 'ARM',
    0x0100000c: 'ARM64',
    0x00000012: 'POWERPC',
    0x01000012: 'POWERPC64',
}

MH_PIE = 0x200000               # Flag to be disabled

MAGIC_IS_INVALID = 0x00
MAGIC_IS_FAT = 0x01
MAGIC_IS_MACHO32 = 0x02
MAGIC_IS_MACHO64 = 0x03


def sskaje():
    """ Copyright """
    print 'Mach-o PIE Remover v0.1'
    print 'Author: sskaje (https://sskaje.me/)'


def usage(errmsg=""):
    """ Usage """
    if errmsg != "":
        print "*** Error: " + errmsg + " ***"

    print "Usage: python " + sys.argv[0] + " /PATH/TO/BINARY"
    print ''
    sys.exit(1)


def error(errmsg):
    print "*** Error: " + errmsg + " ***"
    sys.exit(2)


def process_flags(content, start_pos, is_big_endian=True):
    """ Process flags and disable PIE, start_pos should be the next pos after magic number """
    if is_big_endian:
        unpack_param = '>IIIIII'
    else:
        unpack_param = '<IIIIII'

    header = content[start_pos:start_pos+MACH_HEADER_MIN_LENGTH]
    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(unpack_param, header)

    print "[i] CPU Type: " + CPU_TYPES[cputype]

    if flags & MH_PIE:
        print "[*] MH_PIE enabled"
        flags &= ~MH_PIE
        content = content[0:start_pos + 20] + struct.pack('I', flags) + content[start_pos + 24:]
        print "[*] MH_PIE now disabled!"
    else:
        print "[*] MH_PIE not enabled, nothing to do with it"

    return content


def process_fat(content, is_big_endian):
    # find all archs
    # process one by one
    print "Processing fat binary"
    if is_big_endian:
        pack_param_prefix = '>'
    else:
        pack_param_prefix = '<'

    magic, nfat_arch = struct.unpack(pack_param_prefix + 'II', str(content[0:FAT_HEADER_LENGTH]))
    print "%d arch(s) found!" % nfat_arch

    i = 0
    begin = FAT_HEADER_LENGTH

    while i < nfat_arch:
        h = str(content[begin:begin + FAT_ARCH_LENGTH])
        cputype, cpusubtype, offset, size, align = struct.unpack(pack_param_prefix + 'IIIII', h)

        print "====\t%d\t====" % i
        print "[i] CPU:\t%s" % CPU_TYPES[cputype]
        print "[i] Offset:\t0x%08x" % offset
        print "[i] Size:\t0x%08x" % size

        # find the magic and check if this is a 32/64 bit app
        thin_magic = content[offset:(offset+MAGIC_LENGTH)]
        magic_type, _is_big_endian = test_magic(thin_magic)

        if magic_type == MAGIC_IS_MACHO64 or magic_type == MAGIC_IS_MACHO32:
            content = process_flags(content, offset + MAGIC_LENGTH, _is_big_endian)
        else:
            print "[X] Invalid magic %08x" % struct.unpack(pack_param_prefix + 'I', thin_magic)

        begin += FAT_ARCH_LENGTH
        i += 1

    return content


def backup_file(filename):
    """ Save target file to target.bak """
    shutil.copyfile(filename, filename+".bak")


def test_magic(magic):
    """ Find out what the magic number is and if it is big endian """
    if magic == struct.pack('>I', FAT_MAGIC):
        return MAGIC_IS_FAT, True
    elif magic == struct.pack('<I', FAT_MAGIC):
        return MAGIC_IS_FAT, False
    elif magic == struct.pack('>I', MACH_O_MAGIC_64):
        return MAGIC_IS_MACHO64, True
    elif magic == struct.pack('<I', MACH_O_MAGIC_64):
        return MAGIC_IS_MACHO64, False
    elif magic == struct.pack('>I', MACH_O_MAGIC_32):
        return MAGIC_IS_MACHO32, True
    elif magic == struct.pack('<I', MACH_O_MAGIC_32):
        return MAGIC_IS_MACHO32, False
    else:
        return MAGIC_IS_INVALID, False


def main():
    sskaje()
    if len(sys.argv) < 2:
        usage()

    filename = sys.argv[1]

    if not os.path.exists(filename):
        usage("File not found")

    if not os.path.isfile(filename):
        usage("Invalid file")

    try:
        print "[i] Backup " + filename + " to " + filename + ".bak"
        backup_file(filename)

        fp = open(filename, 'rb')
        fp.seek(0)
        content = fp.read()
        fp.close()

        # Read first 4 bytes
        magic = content[0:MAGIC_LENGTH]
        magic_type, is_big_endian = test_magic(magic)

        if magic_type == MAGIC_IS_FAT:
            print "[i] This is a fat binary/universal binary"
            content = process_fat(content, is_big_endian)

        elif magic_type == MAGIC_IS_MACHO64:
            print "[i] This is a 64-bit thin binary"
            content = process_flags(content, MAGIC_LENGTH, is_big_endian)

        elif magic_type == MAGIC_IS_MACHO32:
            print "[i] This is a 32-bit thin binary "
            content = process_flags(content, MAGIC_LENGTH, is_big_endian)

        else:
            raise Exception("Not a mach-o binary")

        # Save content
        fp = open(filename, 'wb')
        fp.write(content)
        fp.close()

    except Exception, e:
        error(str(e))

if __name__ == "__main__":
    main()

# EOF
