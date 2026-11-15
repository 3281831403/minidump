
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.common_structs import MINIDUMP_LOCATION_DESCRIPTOR
from minidump.exceptions import MinidumpBoundaryException

class MINIDUMP_DIRECTORY:
	def __init__(self):
		self.StreamType = None
		self.Location = None

	def to_bytes(self):
		t = self.StreamType.value.to_bytes(4, byteorder = 'little', signed = False)
		t += self.Location.to_bytes()
		return t

	@staticmethod
	def get_stream_type_value(buff, peek=False):
		return int.from_bytes(buff.read(4), byteorder = 'little', signed = False)

	@staticmethod
	def parse(buff):

		raw_stream_type_value = MINIDUMP_DIRECTORY.get_stream_type_value(buff)

		# StreamType value that are over 0xffff are considered MINIDUMP_USER_STREAM streams
		# and their format depends on the client used to create the minidump.
		# As per the documentation, this stream should be ignored : https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidumminidump_dirp_stream_type#remarks
		is_user_stream = raw_stream_type_value > MINIDUMP_STREAM_TYPE.LastReservedStream.value
		is_stream_supported = raw_stream_type_value in MINIDUMP_STREAM_TYPE._value2member_map_
		if is_user_stream and not is_stream_supported:
			return None

		md = MINIDUMP_DIRECTORY()
		if is_stream_supported:
			md.StreamType = MINIDUMP_STREAM_TYPE(raw_stream_type_value)
		else:
			# Unknown but in-range stream type. Keep the raw integer so the
			# caller can validate its location and then skip it.
			md.StreamType = raw_stream_type_value
		md.Location = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)

		check_rva = getattr(buff, 'check_rva', None)
		if check_rva is not None:
			check_rva(md.Location.Rva, md.Location.DataSize, what='stream directory')
		return md

	@staticmethod
	async def aparse(buff):

		t = await buff.read(4)
		if len(t) != 4:
			from minidump.exceptions import MinidumpMalformedFileException
			raise MinidumpMalformedFileException(
				'Truncated stream directory: expected 4 bytes for the stream type but got %d' % len(t)
			)
		raw_stream_type_value = int.from_bytes(t, byteorder = 'little', signed = False)

		# StreamType value that are over 0xffff are considered MINIDUMP_USER_STREAM streams
		# and their format depends on the client used to create the minidump.
		# As per the documentation, this stream should be ignored : https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidumminidump_dirp_stream_type#remarks
		is_user_stream = raw_stream_type_value > MINIDUMP_STREAM_TYPE.LastReservedStream.value
		is_stream_supported = raw_stream_type_value in MINIDUMP_STREAM_TYPE._value2member_map_
		if is_user_stream and not is_stream_supported:
			return None

		md = MINIDUMP_DIRECTORY()
		if is_stream_supported:
			md.StreamType = MINIDUMP_STREAM_TYPE(raw_stream_type_value)
		else:
			md.StreamType = raw_stream_type_value
		md.Location = await MINIDUMP_LOCATION_DESCRIPTOR.aparse(buff)

		check_rva = getattr(buff, 'check_rva', None)
		if check_rva is not None:
			check_rva(md.Location.Rva, md.Location.DataSize, what='stream directory')
		return md

	def __str__(self):
		t = 'StreamType: %s %s' % (self.StreamType, self.Location)
		return t
