import sys

from boofuzz import s_initialize, s_static, s_get, s_random, s_block
from common import setup_session


def initialize_goose(session):
    s_initialize('goose_msg')

    with s_block("Preamble"):
        s_static('\x01\x0c\xcd\x01\x00\x01', name="Destination")
        s_static('\x00\x00\x00\x00\x00\x00', name="Source")
        s_static('\x81\x00', name="Tag Protocol Identifier (TPID)")
        s_static('\x80\x00', name="Tag Control Information (TCI)")
        s_static('\x88\xb8', name="Ethertype = Goose")
        s_static('\x03\xe8', name="Application Identifier (APPID) laut Paper allerdings x3f xff")
        s_static('\x00\xb7', name="Length (183) --> Wovon?")
        s_static('\x00\x00', name="Reserved 1")
        s_static('\x00\x00', name="Reserved 2")

    with s_block("goosePDU"):
        s_random('\x61', min_length=0, max_length=100, num_mutations=100000, name="TAG goosePDU")
        s_random('\x81\xac', min_length=0, max_length=100, num_mutations=100000, name="LENGTH goosePDU  (172)")

    with s_block("gocbRef"):
        s_random("\x80", min_length=0, max_length=100, num_mutations=100000, name="TAG gocbRef")
        s_random("\x29", min_length=0, max_length=100, num_mutations=100000, name="LENGTH gocbRef = 41")
        s_random("\x73\x69\x6d\x70\x6c\x65\x49\x4f\x47\x65"
                 "\x6e\x65\x72\x69\x63\x49\x4f\x2f\x4c\x4c"
                 "\x4e\x30\x24\x47\x4f\x24\x67\x63\x62\x41"
                 "\x6e\x61\x6c\x6f\x67\x56\x61\x6c\x75\x65"
                 "\x73", min_length=0, max_length=100, num_mutations=100000, name="DATA gocbRef")

    with s_block("TimeAllowedToLive"):
        s_random("\x81", min_length=0, max_length=100, num_mutations=100000, name="TAG TimeAllowedToLive")
        s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH TimeAllowedToLive = 1")
        s_random("\x00", min_length=0, max_length=100, num_mutations=100000, name="DATA TimeAllowedToLive")

    with s_block("datSet"):
        s_random("\x82", min_length=0, max_length=100, num_mutations=100000, name="TAG datSet")
        s_random("\x23", min_length=0, max_length=100, num_mutations=100000, name="Length datSet = 35")
        s_random("\x73\x69\x6d\x70\x6c\x65\x49\x4f\x47\x65"
                 "\x6e\x65\x72\x69\x63\x49\x4f\x2f\x4c\x4c"
                 "\x4e\x30\x24\x41\x6e\x61\x6c\x6f\x67\x56"
                 "\x61\x6c\x75\x65\x73", min_length=0, max_length=100, num_mutations=100000, name="DATA datSet")

    with s_block("goID"):
        s_random("\x83", min_length=0, max_length=100, num_mutations=100000, name="TAG goID")
        s_random("\x29", min_length=0, max_length=100, num_mutations=100000, name="LENGTH goID = 41")
        s_random("\x73\x69\x6d\x70\x6c\x65\x49\x4f\x47\x65"
                 "\x6e\x65\x72\x69\x63\x49\x4f\x2f\x4c\x4c"
                 "\x4e\x30\x24\x47\x4f\x24\x67\x63\x62\x41"
                 "\x6e\x61\x6c\x6f\x67\x56\x61\x6c\x75\x65"
                 "\x73", min_length=0, max_length=100, num_mutations=100000, name="DATA goID")

    with s_block("time"):
        s_random("\x84", min_length=0, max_length=100, num_mutations=100000, name="TAG time")
        s_random("\x08", min_length=0, max_length=100, num_mutations=100000, name="LENGTH time = 8")
        s_random("\x5d\xe6\x60\x85\xb8\xd4\xfd\x0a", min_length=0, max_length=100, num_mutations=100000, name="DATA time")

    with s_block("stNum"):
        s_random("\x85", min_length=0, max_length=100, num_mutations=100000, name="TAG stNum")
        s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH stNum = 1")
        s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA stNum")

    with s_block("sqNum"):
        s_random("\x86", min_length=0, max_length=100, num_mutations=100000, name="TAG sqNum")
        s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH sqNum = 1")
        s_random("\x00", min_length=0, max_length=100, num_mutations=100000, name="DATA sqNum")

    with s_block("Test Bit"):
        s_random("\x87", min_length=0, max_length=100, num_mutations=100000, name="TAG Test Bit")
        s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH Test Bit = 1")
        s_random("\x00", min_length=0, max_length=100, num_mutations=100000, name="DATA Test Bit")

    with s_block("ConfRev"):
        s_random("\x88", min_length=0, max_length=100, num_mutations=100000, name="TAG ConfRev")
        s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH ConfRev = 1")
        s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA ConfRev")

    with s_block("ndsCom"):
        s_random("\x89", min_length=0, max_length=100, num_mutations=100000, name="TAG ndsCom")
        s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH ndsCom = 1")
        s_random("\x00", min_length=0, max_length=100, num_mutations=100000, name="DATA ndsCom")

    with s_block("numDatSetEntries"):
        s_random("\x8a", min_length=0, max_length=100, num_mutations=100000, name="TAG numDatSetEntries")
        s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH numDatSetEntries = 1")
        s_random("\x03", min_length=0, max_length=100, num_mutations=100000, name="DATA numDatSetEntries")

    with s_block("allData"):
        s_random("\xab", min_length=0, max_length=100, num_mutations=100000, name="TAG allData")
        s_random("\x10", min_length=0, max_length=100, num_mutations=100000, name="LENGTH allData = 16")

    with s_block("data 1"):
        s_random("\x85", min_length=0, max_length=100, num_mutations=100000, name="TAG data 1 = integer")
        s_random("\x02", min_length=0, max_length=100, num_mutations=100000, name="LENGTH data 1 = 2")
        s_random("\x04\xd2", min_length=0, max_length=100, num_mutations=100000, name="DATA data 1")

    with s_block("data 2"):
        s_random("\x8c", min_length=0, max_length=100, num_mutations=100000, name="TAG data 2 = binary-time")
        s_random("\x06", min_length=0, max_length=100, num_mutations=100000, name="LENGTH data 2 = 6")
        s_random("\x00\x00\x00\x00\x00\x00", min_length=0, max_length=100, num_mutations=100000, name="DATA data 2")

    with s_block("data 3"):
        s_random("\x85", min_length=0, max_length=100, num_mutations=100000, name="TAG data 3 = integer")
        s_random("\x02", min_length=0, max_length=100, num_mutations=100000, name="LENGTH data 3 = 2")
        s_random("\x16\x2e", min_length=0, max_length=100, num_mutations=100000, name="DATA data 3")

    session.connect(s_get('goose_msg'))


def fuzz_goose():
    try:
        session = setup_session(protocol='goose')
    except ValueError as value_error:
        sys.stderr.write('Error: {}'.format(value_error))
        return 1

    initialize_goose(session)

    session.fuzz()

    return 0


if __name__ == '__main__':
    sys.exit(fuzz_goose())
