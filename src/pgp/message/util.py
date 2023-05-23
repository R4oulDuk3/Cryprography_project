import struct


def write_chunk(chunk):
    return struct.pack('!I', len(chunk)) + chunk


def read_chunk(data: bytes, offset: int):
    size = struct.unpack_from('!I', data, offset)[0]
    offset += 4
    value = data[offset: offset + size]
    offset += size
    return value, offset
