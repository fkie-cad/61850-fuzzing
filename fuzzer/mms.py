import sys

from boofuzz import s_initialize, s_get, s_random, s_block
from common import setup_session


def initialize_mms(session):
    s_initialize('mms_msg')

    with s_block("TPKT"):
        s_random("\x03", min_length=0, max_length=100, num_mutations=100000, name="TPKT Version = 3")
        s_random("\x00", min_length=0, max_length=100, num_mutations=100000, name="TPKT Reserved = 0")
        s_random("\x00\xbb", min_length=0, max_length=100, num_mutations=100000, name="TPKT Length = 187")

    # ----------------------

    with s_block("COTP"):
        s_random("\x02", min_length=0, max_length=100, num_mutations=100000, name="COTP Length = 2")
        s_random("\xf0", min_length=0, max_length=100, num_mutations=100000, name="COTP PDU Type = DT Data (0x0f)")
        s_random("\x80", min_length=0, max_length=100, num_mutations=100000, name="COTP TPDU number = 0 and COTP Last data unit = yes")

    # ----------------------

    with s_block("ISO 8327-1 OSI Session Protocol"):
        s_random("\x0d", min_length=0, max_length=100, num_mutations=100000, name="SPDU Type: CONNECT (CN) SPDU (13)")
        s_random("\xb2", min_length=0, max_length=100, num_mutations=100000, name="Length: 178")

        with s_block("Connect Accept Item"):
            s_random("\x05", min_length=0, max_length=100, num_mutations=100000, name="Parameter type: Connect Accept Item (5)")
            s_random("\x06", min_length=0, max_length=100, num_mutations=100000, name="Parameter 1 length: 6")

            with s_block("Protocol Options"):
                s_random("\x13", min_length=0, max_length=100, num_mutations=100000, name="Parameter type: Protocol Options (19)")
                s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="Parameter length: 1")
                s_random("\x00", min_length=0, max_length=100, num_mutations=100000, name="Flags: 0x00")

            with s_block("Version Number"):
                s_random("\x16", min_length=0, max_length=100, num_mutations=100000, name="Parameter type: Version Number (22)")
                s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="Parameter 2 length: 1")

            s_random("\x02", min_length=0, max_length=100, num_mutations=100000, name="Flags: 0x02, Protocol Version 2")

        with s_block("Session Requirement"):
            s_random("\x14", min_length=0, max_length=100, num_mutations=100000, name="Parameter type: Session Requirement (20)")
            s_random("\x02", min_length=0, max_length=100, num_mutations=100000, name="Parameter 3 length: 2")
            s_random("\x00\x02", min_length=0, max_length=100, num_mutations=100000, name="Flags: 0x0002, Duplex functional unit")

        with s_block("Calling Session Selector"):
            s_random("\x33", min_length=0, max_length=100, num_mutations=100000, name="Parameter type: Calling Session Selector (51)")
            s_random("\x02", min_length=0, max_length=100, num_mutations=100000, name="Parameter 4 length: 2")
            s_random("\x00\x01", min_length=0, max_length=100, num_mutations=100000, name="Calling Session Selector: 0001")

        with s_block("Called Session Selector"):
            s_random("\x34", min_length=0, max_length=100, num_mutations=100000, name="Parameter type: Called Session Selector (52)")
            s_random("\x02", min_length=0, max_length=100, num_mutations=100000, name="Parameter 5 length: 2")
            s_random("\x00\x01", min_length=0, max_length=100, num_mutations=100000, name="Called Session Selector: 0001")

        with s_block("Session user data"):
            s_random("\xc1", min_length=0, max_length=100, num_mutations=100000, name="Parameter type: Session user data (193)")
            s_random("\x9c", min_length=0, max_length=100, num_mutations=100000, name="Parameter 6 length: 156")

    # ----------------------

    with s_block("ISO 8823 OSI Presentation Protocol"):
        s_random("\x31\x81", min_length=0, max_length=100, num_mutations=100000, name="TAG CP-TYPE")
        s_random("\x99", min_length=0, max_length=100, num_mutations=100000, name="LENGTH CP-TYPE = 153")

        with s_block("mode selector"):
            s_random("\xa0", min_length=0, max_length=100, num_mutations=100000, name="TAG mode selector")
            s_random("\x03", min_length=0, max_length=100, num_mutations=100000, name="LENGTH mode selector = 3")

            with s_block("mode-value"):
                s_random("\x80", min_length=0, max_length=100, num_mutations=100000, name="TAG mode-value")
                s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH mode-value = 1")
                s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA mode-value = normal-mode (1)")

        with s_block("normal-mode-parameters"):
            s_random("\xa2\x81", min_length=0, max_length=100, num_mutations=100000, name="TAG normal-mode-parameters")
            s_random("\x91", min_length=0, max_length=100, num_mutations=100000, name="LENGTH normal-mode-parameters = 145")

        with s_block("calling-presentation-selector"):
            s_random("\x81", min_length=0, max_length=100, num_mutations=100000, name="TAG calling-presentation-selector")
            s_random("\x04", min_length=0, max_length=100, num_mutations=100000, name="LENGTH calling-presentation-selector = 4")
            s_random("\x00\x00\x00\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA calling-presentation-selector = 00000001")

        with s_block("called-presentation-selector"):
            s_random("\x82", min_length=0, max_length=100, num_mutations=100000, name="TAG called-presentation-selector")
            s_random("\x04", min_length=0, max_length=100, num_mutations=100000, name="LENGTH called-presentation-selector = 4")
            s_random("\x00\x00\x00\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA called-presentation-selector = 00000001")

        with s_block("presentation-context-definition-list"):
            s_random("\xa4", min_length=0, max_length=100, num_mutations=100000, name="TAG presentation-context-definition-list")
            s_random("\x23", min_length=0, max_length=100, num_mutations=100000, name="LENGTH presentation-context-definition-list = 35")

            with s_block("Context-list item 1"):
                s_random("\x30", min_length=0, max_length=100, num_mutations=100000, name="TAG Context-list item 1")
                s_random("\x0f", min_length=0, max_length=100, num_mutations=100000, name="LENGTH Context-list item 1 = 15")

                with s_block("presentation-context-identifier 1"):
                    s_random("\x02", min_length=0, max_length=100, num_mutations=100000, name="TAG presentation-context-identifier 1")
                    s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH presentation-context-identifier 1 = 1")
                    s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA presentation-context-identifier 1 =  1")

                with s_block("abstract-syntax-name 1"):
                    s_random("\x06", min_length=0, max_length=100, num_mutations=100000, name="TAG abstract-syntax-name 1")
                    s_random("\x04", min_length=0, max_length=100, num_mutations=100000, name="LENGTH abstract-syntax-name 1 = 4")
                    s_random("\x52\x01\x00\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA abstract-syntax-name 1")

                with s_block("transfer-syntax-name-list 1"):
                    s_random("\x30", min_length=0, max_length=100, num_mutations=100000, name="TAG transfer-syntax-name-list 1")
                    s_random("\x04", min_length=0, max_length=100, num_mutations=100000, name="LENGTH transfer-syntax-name-list 1 = 4")
                    s_random("\x06\x02\x51\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA transfer-syntax-name-list 1")

            with s_block("Context-list item 2"):
                s_random("\x30", min_length=0, max_length=100, num_mutations=100000, name="TAG Context-list item 2")
                s_random("\x10", min_length=0, max_length=100, num_mutations=100000, name="LENGTH Context-list item 2 = 16")

                with s_block("presentation-context-identifier 2"):
                    s_random("\x02", min_length=0, max_length=100, num_mutations=100000, name="TAG presentation-context-identifier 2")
                    s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH presentation-context-identifier 2 = 1")
                    s_random("\x03", min_length=0, max_length=100, num_mutations=100000, name="DATA presentation-context-identifier 2 =  1")

                with s_block("abstract-syntax-name 2"):
                    s_random("\x06", min_length=0, max_length=100, num_mutations=100000, name="TAG abstract-syntax-name 2")
                    s_random("\x05", min_length=0, max_length=100, num_mutations=100000, name="LENGTH abstract-syntax-name 2 = 5")
                    s_random("\x28\xca\x22\x02\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA abstract-syntax-name 2")

                with s_block("transfer-syntax-name-list 2"):
                    s_random("\x30", min_length=0, max_length=100, num_mutations=100000, name="TAG transfer-syntax-name-list 2")
                    s_random("\x04", min_length=0, max_length=100, num_mutations=100000, name="LENGTH transfer-syntax-name-list 2 = 4")
                    s_random("\x06\x02\x51\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA transfer-syntax-name-list 2")

        with s_block("user-data"):
            s_random("\x61", min_length=0, max_length=100, num_mutations=100000, name="TAG user-data")
            s_random("\x5e", min_length=0, max_length=100, num_mutations=100000, name="LENGTH user-data = 94")

            with s_block("PDV-list"):
                s_random("\x30", min_length=0, max_length=100, num_mutations=100000, name="TAG PDV-list")
                s_random("\x5c", min_length=0, max_length=100, num_mutations=100000, name="LENGTH PDV-list = 92")

            with s_block("presentation-context-identifier"):
                s_random("\x02", min_length=0, max_length=100, num_mutations=100000, name="TAG presentation-context-identifier")
                s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH presentation-context-identifier = 1")
                s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA presentation-context-identifier = 1")

            with s_block("presentation-data-values"):
                s_random("\xa0", min_length=0, max_length=100, num_mutations=100000, name="TAG presentation-data-values")
                s_random("\x57", min_length=0, max_length=100, num_mutations=100000, name="LENGTH presentation-data-values = 87")

    # ----------------------

    with s_block("ISO 8650-1 OSI Association Control Service"):
        s_random("\x60", min_length=0, max_length=100, num_mutations=100000, name="TAG aarq")
        s_random("\x55", min_length=0, max_length=100, num_mutations=100000, name="LENGTH aarq = 85")

        with s_block("?"):
            s_random("\xa1", min_length=0, max_length=100, num_mutations=100000, name="TAG ?")
            s_random("\x07", min_length=0, max_length=100, num_mutations=100000, name="LENGTH ? = 7")

        with s_block("aSO-context-name"):
            s_random("\x06", min_length=0, max_length=100, num_mutations=100000, name="TAG aSO-context-name")
            s_random("\x05", min_length=0, max_length=100, num_mutations=100000, name="LENGTH aSO-context-name = 5")
            s_random("\x28\xca\x22\x02\x03", min_length=0, max_length=100, num_mutations=100000, name="DATA aSO-context-name = 1.0.9506.2.3 (MMS)")

        with s_block("called-AP-title"):
            s_random("\xa2", min_length=0, max_length=100, num_mutations=100000, name="TAG called-AP-title")
            s_random("\x07", min_length=0, max_length=100, num_mutations=100000, name="LENGTH called-AP-title = 7")
            s_random("\x06\x05\x29\x01\x87\x67\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA called-AP-title)")

        with s_block("called-AE-qualifier"):
            s_random("\xa3", min_length=0, max_length=100, num_mutations=100000, name="TAG called-AE-qualifier")
            s_random("\x03", min_length=0, max_length=100, num_mutations=100000, name="LENGTH called-AE-qualifier = 3")
            s_random("\x02\x01\x0c", min_length=0, max_length=100, num_mutations=100000, name="DATA called-AE-qualifier")

        with s_block("calling-AP-title"):
            s_random("\xa6", min_length=0, max_length=100, num_mutations=100000, name="TAG calling-AP-title")
            s_random("\x06", min_length=0, max_length=100, num_mutations=100000, name="LENGTH calling-AP-title = 6")
            s_random("\x06\x04\x29\x01\x87\x67", min_length=0, max_length=100, num_mutations=100000, name="DATA calling-AP-title")

        with s_block("calling-AE-qualifier"):
            s_random("\xa7", min_length=0, max_length=100, num_mutations=100000, name="TAG calling-AE-qualifier")
            s_random("\x03", min_length=0, max_length=100, num_mutations=100000, name="LENGTH calling-AE-qualifier = 3")
            s_random("\x02\x01\x0c", min_length=0, max_length=100, num_mutations=100000, name="DATA calling-AE-qualifier")

        with s_block("user-information"):
            s_random("\xbe", min_length=0, max_length=100, num_mutations=100000, name="TAG user-information")
            s_random("\x2f", min_length=0, max_length=100, num_mutations=100000, name="LENGTH user-information = 47")

        with s_block("Association-data"):
            s_random("\x28", min_length=0, max_length=100, num_mutations=100000, name="TAG Association-data")
            s_random("\x2d", min_length=0, max_length=100, num_mutations=100000, name="LENGTH Association-data = 45")

        with s_block("indirect-reference"):
            s_random("\x02", min_length=0, max_length=100, num_mutations=100000, name="TAG indirect-reference")
            s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH indirect-reference = 1")
            s_random("\x03", min_length=0, max_length=100, num_mutations=100000, name="DATA indirect-reference = 3")

        with s_block("encoding: single-ASN1-type"):
            s_random("\xa0", min_length=0, max_length=100, num_mutations=100000, name="TAG encoding: single-ASN1-type (0)")
            s_random("\x28", min_length=0, max_length=100, num_mutations=100000, name="LENGTH encoding: single-ASN1-type (0) = 40")

    # ----------------------

    with s_block("MMS"):
        s_random("\xa8", min_length=0, max_length=100, num_mutations=100000, name="TAG initiate-RequestPDU")
        s_random("\x26", min_length=0, max_length=100, num_mutations=100000, name="LENGTH initiate-RequestPDU = 38")

        with s_block("localDetailCalling"):
            s_random("\x80", min_length=0, max_length=100, num_mutations=100000, name="TAG localDetailCalling")
            s_random("\x03", min_length=0, max_length=100, num_mutations=100000, name="LENGTH localDetailCalling = 3")
            s_random("\x00\xfd\xe8", min_length=0, max_length=100, num_mutations=100000, name="DATA localDetailCalling = 65000")

        with s_block("proposedMaxServOutstandingCalling"):
            s_random("\x81", min_length=0, max_length=100, num_mutations=100000, name="TAG proposedMaxServOutstandingCalling")
            s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH proposedMaxServOutstandingCalling = 1")
            s_random("\x05", min_length=0, max_length=100, num_mutations=100000, name="DATA proposedMaxServOutstandingCalling = 5")

        with s_block("proposedMaxServOutstandingCalled"):
            s_random("\x82", min_length=0, max_length=100, num_mutations=100000, name="TAG proposedMaxServOutstandingCalled")
            s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH proposedMaxServOutstandingCalled = 1")
            s_random("\x05", min_length=0, max_length=100, num_mutations=100000, name="DATA proposedMaxServOutstandingCalled = 5")

        with s_block("proposedDataStructureNestingLevel"):
            s_random("\x83", min_length=0, max_length=100, num_mutations=100000, name="TAG proposedDataStructureNestingLevel")
            s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH proposedDataStructureNestingLevel = 1")
            s_random("\x0a", min_length=0, max_length=100, num_mutations=100000, name="DATA proposedDataStructureNestingLevel = 10")

        with s_block("mmsInitRequestDetail"):
            s_random("\xa4", min_length=0, max_length=100, num_mutations=100000, name="TAG mmsInitRequestDetail")
            s_random("\x16", min_length=0, max_length=100, num_mutations=100000, name="LENGTH mmsInitRequestDetail = 22")

        with s_block("proposedVersionNumber"):
            s_random("\x80", min_length=0, max_length=100, num_mutations=100000, name="TAG proposedVersionNumber")
            s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="LENGTH proposedVersionNumber = 1")
            s_random("\x01", min_length=0, max_length=100, num_mutations=100000, name="DATA proposedVersionNumber = 1")

        with s_block("Padding 1"):
            s_random("\x81", min_length=0, max_length=100, num_mutations=100000, name="TAG Padding 1")
            s_random("\x03", min_length=0, max_length=100, num_mutations=100000, name="LENGTH Padding 1 = 3")
            s_random("\x05\xf1\x00", min_length=0, max_length=100, num_mutations=100000, name="DATA Padding 1: = 5 & proposedParameterCBB: f100")

        with s_block("Padding 2"):
            s_random("\x82", min_length=0, max_length=100, num_mutations=100000, name="TAG Padding 2")
            s_random("\x0c", min_length=0, max_length=100, num_mutations=100000, name="LENGTH Padding 2 = 12")
            s_random("\x03\xee\x1c\x00\x00\x04\x08\x00\x00\x79\xef\x18", min_length=0, max_length=100, num_mutations=100000, name="DATA Padding 2: = 3 & servicesSupportedCalling")

    session.connect(s_get('mms_msg'))


def fuzz_mms():
    try:
        session = setup_session(protocol='mms')
    except ValueError as value_error:
        sys.stderr.write('Error: {}'.format(value_error))
        return 1

    initialize_mms(session)

    session.fuzz()

    return 0


if __name__ == '__main__':
    sys.exit(fuzz_mms())
