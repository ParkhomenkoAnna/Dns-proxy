import struct


QR = dict([(0, 'QUERY'), (1, 'RESPONSE')])
OPCODE = dict([(0, 'QUERY'), (1, 'IQUERY'), (2, 'STATUS'), (5, 'UPDATE')])
RCODE = dict([(0, 'NO ERROR'), (2, 'SERVER FAILURE'), (3, 'NAME ERROR'), (4, 'NOT IMPLEMENTED'), (5, 'REFUSE')])
TYPE = dict([(1, 'A'), (2, 'NS'), (5, 'CNAME'), (12, 'PTR'), (13, 'HINFO'), (15, 'MX'), (252, 'AXFR'), (255, 'ANY')])
CLASS = dict([(1, 'IN'), (2, 'CS'), (3, 'CH'), (4, 'Hesiod'), (254, 'None'), (255, ' *')])


def bin_to_dec(seq):
    size = len(seq)
    result = 0
    for i in range(0, size):
        if int(seq[i]) == 1:
            result += 2**(size-i-1)
    return result


class DnsFlags(object):
    def __init__(self, qr=None, opcode=None, aa=None, tc=None, rd=None, ra=None, null=None, rcode=None):
        self.qr = int(qr)
        self.opcode = opcode
        self.aa = aa or 0
        self.tc = tc or 0
        self.rd = rd or 0
        self.ra = ra or 0
        self.null = null or '000'
        self.rcode = rcode

        return

    @classmethod
    def parse_flags(cls, flags):
        bits = bin(flags)[2:].zfill(16)
        qr = bits[0]
        opcode = bits[1:5]
        aa = bits[5]
        tc = bits[6]
        rd = bits[7]
        ra = bits[8]
        null = bits[9:12]
        rcode = bits[12:16]
        return cls(qr, str(opcode), aa, tc, rd, ra, null, rcode)

    @classmethod
    def pack_flags(cls, flags):
        qr = flags.qr
        opcode = flags.opcode
        aa = flags.aa
        tc = flags.tc
        rd = flags.rd
        ra = flags.ra
        null = flags.null
        rcode = flags.rcode
        binary_value = str(qr) + str(opcode) + str(aa) + str(tc) + str(rd) + str(ra) + str(null) + str(rcode)
        dec_value = bin_to_dec(binary_value)
        return dec_value


class DnsHeader():
    def __init__(self, id, flags, questions, answer, authority,  additional):
        self.id = id
        self.flags = flags
        self.questions = questions
        self.answer = answer
        self.authority = authority
        self.additional = additional
        return

    @classmethod
    def parse_header(self, buffer):
        id, all_flags, questions, answer, authority, additional = struct.unpack_from("!HHHHHH", buffer[:12])
        flag = DnsFlags.parse_flags(all_flags)
        return self(id, flag, questions, answer, authority, additional)

    @classmethod
    def pack_header(self, header):
        pack_header = struct.pack("!H", header.id)
        flags = DnsFlags.pack_flags(header.flags)
        pack_header += struct.pack("!H", flags)
        pack_header += struct.pack("!H", header.questions)
        pack_header += struct.pack("!H", header.answer)
        pack_header += struct.pack("!H", header.authority)
        pack_header += struct.pack("!H", header.additional)
        return pack_header


class DnsAnswers():
    def __init__(self, rname, rtype, rclass, ttl=None, length=None, label=None):
        self.rname = rname
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.length = length
        self.label = label
        return

    @classmethod
    def parse_answer(cls, buffer):
        pass


class DnsQueries():
    def __init__(self, qname, qtype, qclass):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    @classmethod
    def get_query_name(cls, buffer):
        qname = ""
        counter_size = 1
        counter, = struct.unpack_from("!b", buffer)
        start = counter_size
        while counter != 0:
            end = start + counter
            qname += buffer[start:end].decode("utf-8")
            start = end
            counter, = struct.unpack_from("!b", buffer[start:])
            if counter != 0:
                qname += "."
            start += counter_size
        return qname, buffer[start:]

    @classmethod
    def parse_query(cls, buffer):
        qname, buffer = cls.get_query_name(buffer)
        qtype, qclass = struct.unpack_from("!HH", buffer)
        return cls(qname, qtype, qclass), buffer

    @classmethod
    def pack_query(cls, query):
        data = bytearray(b'')
        count = 0
        null = 0
        query.qname += "."
        start = 0
        all_count = 0
        for char in query.qname:
            if char != ".":
                count = count+1
            else:
                data += struct.pack("!b", count)
                data += bytes(query.qname[start:start+count].encode("ascii"))
                start += count+1
                all_count += 1
                count = 0
        data += struct.pack("!b", count)
        data += struct.pack("!h", query.qtype)
        data += struct.pack("!h", query.qclass)
        return data


class DnsPacket():
    def __init__(self, header, questions=None, answer=None):
        self.header = header
        self.questions = questions or 0
        self.answer = answer or 0
        return

    @classmethod
    def parse(cls, buffer):
        header_size = 12
        header = DnsHeader.parse_header(buffer[:header_size])
        questions, buffer = DnsQueries.parse_query(buffer[header_size:])
        if header.answer >0:
            # not implemented
            answers = DnsAnswers.parse_answer(buffer)

        return cls(header, questions)

    def info(self):
        return "DNS Header: id=0x%x, type=%s, class=%s, Qtype: %s, Opcode: %s," \
               "\nRcode: %s, Questions(%d): %s, Answers(%d): %s" %  \
               (self.header.id,
                TYPE.get(self.questions.qtype), CLASS.get(self.questions.qclass),
                QR.get(self.header.flags.qr), OPCODE.get(bin_to_dec(self.header.flags.opcode)),
                RCODE.get(bin_to_dec(self.header.flags.rcode)), self.header.questions,
                self.questions.qname, self.header.answer, self.answer)

    @classmethod
    def pack(cls, packet):
        data = bytearray(b'')
        header = DnsHeader.pack_header(packet.header)
        data += header
        questions = DnsQueries.pack_query(packet.questions)
        data += questions
        return bytes(data)


def test():
    flags = DnsFlags(qr='1', opcode='0000', aa='0', tc='0', ra='1', rd='0', rcode='0101')
    header = DnsHeader(5034, flags, 1, 0, 0, 0)
    questions = DnsQueries("apple.com", 1, 1)
    packet = DnsPacket(header, questions)
    print(packet.info())


#test()
