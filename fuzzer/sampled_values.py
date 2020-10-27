import sys

from boofuzz import s_initialize, s_static, s_get, s_random, s_block
from common import setup_session


def initialize_sampled_values(session):
    s_initialize('sv_msg')

    with s_block("Preamble"):
        s_static('\x01\x0c\xcd\x01\x00\x01', name="Destination")
        s_static('\x00\x00\x00\x00\x00\x00', name="Source")
        s_static('\x81\x00', name="Tag Protocol Identifier (TPID)")
        s_static('\x80\x00', name="Tag Control Information (TCI)")
        s_static('\x88\xba', name="Ethertype = Sampled Value Transmission")
        s_static('\x40\x00', name="Application Identifier (APPID)")
        s_static('\x00\x61', name="Length (97)")
        s_static('\x00\x00', name="Reserved 1")
        s_static('\x00\x00', name="Reserved 2")
        s_static('\x60', name="TAG savPDU")
        s_static('\x57', name="LENGTH savPDU = 87")

    with s_block("noASDU"):
        s_random('\x80', min_length=0, max_length=100, num_mutations=100000,
                 name="TAG noASDU")
        s_random('\x01', min_length=0, max_length=100, num_mutations=100000, name="LENGTH noASDU = 1")
        s_random('\x02', min_length=0, max_length=100, num_mutations=100000, name="DATA noASDU = 2")

    with s_block("seqASDU"):
        s_random('\xa2', min_length=0, max_length=100, num_mutations=100000, name="TAG seqASDU")
        s_random('\x52', min_length=0, max_length=100, num_mutations=100000, name="LENGTH seqASDU = 82")

    with s_block("ASDU (1)"):
        s_random('\x30', min_length=0, max_length=100, num_mutations=100000, name="TAG Sequence ASDU (1)")
        s_random('\x27', min_length=0, max_length=100, num_mutations=100000, name="LENGTH Sequence ASDU (1) = 39")

    with s_block("svID 1"):
        s_random('\x80', min_length=0, max_length=100, num_mutations=100000, name="TAG svID 1")
        s_random('\x06', min_length=0, max_length=100, num_mutations=100000, name="LENGTH svID 1 = 6")
        s_random('\x73\x76\x70\x75\x62\x31', min_length=0, max_length=100, num_mutations=100000, name="DATA svID")

    with s_block("smpCnt 1"):
        s_random('\x82', min_length=0, max_length=100, num_mutations=100000, name="TAG smpCnt 1")
        s_random('\x02', min_length=0, max_length=100, num_mutations=100000, name="LENGTH smpCnt 1 = 2")
        s_random('\x00\x01', min_length=0, max_length=100, num_mutations=100000, name="DATA smpCnt 1 = 1")

    with s_block("confRef 1"):
        s_random('\x83', min_length=0, max_length=100, num_mutations=100000, name="TAG confRef 1")
        s_random('\x01', min_length=0, max_length=100, num_mutations=100000, name="LENGTH confRef 1")
        s_random('\x00\x00\x00\x01', min_length=0, max_length=100, num_mutations=100000, name="DATA confRef 1 = 1")

    with s_block("smpSynch 1"):
        s_random('\x85', min_length=0, max_length=100, num_mutations=100000, name="TAG smpSynch 1")
        s_random('\x01', min_length=0, max_length=100, num_mutations=100000, name="LENGTH smpSynch 1")
        s_random('\x00', min_length=0, max_length=100, num_mutations=100000, name="DATA smpSynch 1 = 0")

    with s_block("seqData 1"):
        s_random('\x87', min_length=0, max_length=100, num_mutations=100000, name="TAG seqData 1")
        s_random('\x10', min_length=0, max_length=100, num_mutations=100000, name="LENGTH smpSynch 1 = 16")
        s_random('\x44\x9a\x52\x2b\x3d\xfc\xd3\x5b\x5e\x3a'
                 '\x91\x59\x65\xa1\xca\x00', min_length=0, max_length=100, num_mutations=100000, name="DATA smpSynch 1")

    with s_block("ASDU (2)"):
        s_random('\x30', min_length=0, max_length=100, num_mutations=100000, name="TAG Sequence ASDU (2)")
        s_random('\x27', min_length=0, max_length=100, num_mutations=100000, name="LENGTH Sequence ASDU (2) = 39")

    with s_block("svID 2"):
        s_random('\x80', min_length=0, max_length=100, num_mutations=100000, name="TAG svID 2")
        s_random('\x06', min_length=0, max_length=100, num_mutations=100000, name="LENGTH svID 2 = 6")
        s_random('\x73\x76\x70\x75\x62\x32', min_length=0, max_length=100, num_mutations=100000, name="DATA svID 2")

    with s_block("smpCnt 2"):
        s_random('\x82', min_length=0, max_length=100, num_mutations=100000, name="TAG smpCnt 2")
        s_random('\x02', min_length=0, max_length=100, num_mutations=100000, name="LENGTH smpCnt 2 = 2")
        s_random('\x00\x01', min_length=0, max_length=100, num_mutations=100000, name="DATA smpCnt 2 = 1")

    with s_block("confRef 2"):
        s_random('\x83', min_length=0, max_length=100, num_mutations=100000, name="TAG confRef 2")
        s_random('\x04', min_length=0, max_length=100, num_mutations=100000, name="LENGTH confRef 2 = 4")
        s_random('\x00\x00\x00\x01', min_length=0, max_length=100, num_mutations=100000, name="DATA confRef 2 = 1")

    with s_block("smpSynch 2"):
        s_random('\x85', min_length=0, max_length=100, num_mutations=100000, name="TAG smpSynch 2")
        s_random('\x01', min_length=0, max_length=100, num_mutations=100000, name="LENGTH smpSynch 2 = 1")
        s_random('\x00', min_length=0, max_length=100, num_mutations=100000, name="DATA smpSynch 2 = 0")

    with s_block("seqData 2"):
        s_random('\x87', min_length=0, max_length=100, num_mutations=100000, name="TAG seqData 2")
        s_random('\x10', min_length=0, max_length=100, num_mutations=100000, name="LENGTH seqData 2 = 16")
        s_random('\x45\x1a\x52\x2b\x3e\x7c\xd3\x5b\x5e\x3a'
                 '\x91\x59\x65\xa1\xca\x00', min_length=0, max_length=100, num_mutations=100000, name="DATA seqData 2")

    session.connect(s_get('sv_msg'))


def fuzz_sv():
    try:
        session = setup_session(protocol='sv')
    except ValueError as value_error:
        sys.stderr.write('Error: {}'.format(value_error))
        return 1

    initialize_sampled_values(session)

    session.fuzz()

    return 0


if __name__ == '__main__':
    sys.exit(fuzz_sv())