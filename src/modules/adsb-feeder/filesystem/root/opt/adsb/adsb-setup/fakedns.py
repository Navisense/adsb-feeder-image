# based on code from https://github.com/pathes/fakedns
# (c) 2014 Patryk Hes
# released under the MIT license
import functools as ft
import ipaddress
import logging
import socketserver
import struct
import threading


class Server:
    """Reusable fake DNS server."""
    def __init__(self, *, response_ip: str, non_response_domains: set[str]):
        """
        :param response_ip: The IP with which to respond to all queries.
        :param non_response_domains: A set of domains (including subdomains)
            for which no answer is returned.
        """
        self._make_handler = ft.partial(
            DNSHandler, response_ip, non_response_domains)
        self._server = self._thread = None
        self._logger = logging.getLogger(type(self).__name__)

    def start(self):
        if self._server:
            raise ValueError("already started")
        assert self._thread is None
        self._server = socketserver.ThreadingUDPServer(("", 53),
                                                       self._make_handler)
        self._thread = threading.Thread(target=self._server.serve_forever)
        self._thread.start()
        self._logger.info("Fake DNS server started.")

    def stop(self):
        if not self._server:
            raise ValueError("not started")
        assert self._thread is not None
        self._server.shutdown()
        self._thread.join()
        self._server.server_close()
        self._server = self._thread = None
        self._logger.info("Fake DNS server stopped.")


class DNSHandler(socketserver.BaseRequestHandler):
    DNS_HEADER_LENGTH = 12

    def __init__(
            self, response_ip, non_response_domains: set[str], *args,
            **kwargs):
        self._response_ip = ipaddress.ip_address(response_ip)
        # Non-response domains as lists of encoded domain parts.
        domain_parts = [domain.split(".") for domain in non_response_domains]
        self._non_response_domains = {
            tuple(part.encode()
                  for part in parts)
            for parts in domain_parts}
        self._logger = logging.getLogger(type(self).__name__)
        super().__init__(*args, **kwargs)

    def handle(self):
        socket = self.request[1]
        data = self.request[0]
        nonzeros = data.rstrip("\0".encode())

        # If request doesn't even contain full header, don't respond.
        if len(nonzeros) < self.DNS_HEADER_LENGTH:
            self._logger.warning(
                f"Data length too small: overall {len(data)}, without "
                f"trailing zeros {len(nonzeros)}")
            return

        # Try to read questions - if they're invalid, don't respond.
        try:
            all_questions = self.dns_extract_questions(data)
        except IndexError:
            return

        accepted_questions = [
            q for q in all_questions if self._should_accept_question(q)]

        response = (
            self.dns_response_header(data, len(accepted_questions))
            + self.dns_response_questions(accepted_questions)
            + self.dns_response_answers(accepted_questions))
        socket.sendto(response, self.client_address)

    def _should_accept_question(self, question):
        if any(question["name"][-len(d):] == d
               for d in self._non_response_domains):
            return False
        # Filter only those questions, which have QTYPE=A and QCLASS=IN
        return (
            question["qtype"] == b"\x00\x01"
            and question["qclass"] == b"\x00\x01")

    def dns_extract_questions(self, data):
        """
        Extracts question section from DNS request data.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        questions = []
        # Get number of questions from header's QDCOUNT
        n = (data[4] << 8) + data[5]
        # Where we actually read in data? Start at beginning of question sections.
        pointer = self.DNS_HEADER_LENGTH
        # Read each question section
        for i in range(n):
            length = data[pointer]
            # Read each label from QNAME part
            name_list = []
            while length != 0:
                start = pointer + 1
                end = pointer + length + 1
                name_list.append(data[start:end])
                pointer += length + 1
                length = data[pointer]
            # Read QTYPE
            qtype = data[pointer + 1:pointer + 3]
            # Read QCLASS
            qclass = data[pointer + 3:pointer + 5]
            question = {
                "name": tuple(name_list),
                "qtype": qtype,
                "qclass": qclass,}
            # Move pointer 5 octets further (zero length octet, QTYPE, QNAME)
            pointer += 5
            questions.append(question)
        return questions

    def dns_response_header(self, data, num_answers):
        """
        Generates DNS response header.
        See http://tools.ietf.org/html/rfc1035 4.1.1. Header section format.
        """
        assert num_answers < 2**16
        header = b""
        # ID - copy it from request
        header += data[:2]
        # QR     1    response
        # OPCODE 0000 standard query
        # AA     0    not authoritative
        # TC     0    not truncated
        # RD     0    recursion not desired
        # RA     0    recursion not available
        # Z      000  unused
        # RCODE  0000 no error condition
        header += b"\x80\x00"
        # QDCOUNT - question entries count, set to QDCOUNT from request
        header += data[4:6]
        # ANCOUNT - answer records count, set to number of accepter answers
        header += struct.pack("!H", num_answers)
        # NSCOUNT - authority records count, set to 0
        header += b"\x00\x00"
        # ARCOUNT - additional records count, set to 0
        header += b"\x00\x00"
        return header

    def dns_response_questions(self, questions):
        """
        Generates DNS response questions.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        sections = b""
        for question in questions:
            section = b""
            for label in question["name"]:
                # Length octet
                section += bytes([len(label)])
                section += label
            # Zero length octet
            section += b"\x00"
            section += question["qtype"]
            section += question["qclass"]
            sections += section
        return sections

    def dns_response_answers(self, questions):
        """
        Generates DNS response answers.
        See http://tools.ietf.org/html/rfc1035 4.1.3. Resource record format.
        """
        records = b""
        for question in questions:
            record = b""
            for label in question["name"]:
                # Length octet
                record += bytes([len(label)])
                record += label
            # Zero length octet
            record += b"\x00"
            # TYPE - just copy QTYPE
            # TODO QTYPE values set is superset of TYPE values set, handle different QTYPEs, see RFC 1035 3.2.3.
            record += question["qtype"]
            # CLASS - just copy QCLASS
            # TODO QCLASS values set is superset of CLASS values set, handle at least * QCLASS, see RFC 1035 3.2.5.
            record += question["qclass"]
            # TTL - 32 bit unsigned integer. Set to 0 to inform, that response
            # should not be cached.
            record += b"\x00\x00\x00\x00"
            # RDLENGTH - 16 bit unsigned integer, length of RDATA field.
            # In case of QTYPE=A and QCLASS=IN, RDLENGTH=4.
            record += b"\x00\x04"
            # RDATA - in case of QTYPE=A and QCLASS=IN, it's IPv4 address.
            record += self._response_ip.packed
            records += record
        return records
