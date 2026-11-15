#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
from minidump.common_structs import *
from minidump.exceptions import MinidumpBoundaryException, MinidumpMalformedFileException
from typing import List

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680387(v=vs.85).aspx
class MINIDUMP_MEMORY64_LIST:
	def __init__(self):
		self.NumberOfMemoryRanges:int = None
		self.BaseRva:int = None
		self.MemoryRanges:List[MINIDUMP_MEMORY_DESCRIPTOR64] = []

	def get_size(self):
		return 8 + 8 + len(self.MemoryRanges) * MINIDUMP_MEMORY_DESCRIPTOR64().get_size()

	def to_bytes(self):
		t = len(self.MemoryRanges).to_bytes(8, byteorder = 'little', signed = False)
		t += self.BaseRva.to_bytes(8, byteorder = 'little', signed = False)
		for memrange in self.MemoryRanges:
			t += memrange.to_bytes()
		return t

	@staticmethod
	def parse(buff):
		mml = MINIDUMP_MEMORY64_LIST()
		cnt_raw = buff.read(8)
		base_raw = buff.read(8)
		if len(cnt_raw) != 8 or len(base_raw) != 8:
			raise MinidumpMalformedFileException(
				'Truncated MINIDUMP_MEMORY64_LIST header (expected 16 bytes, got %d)'
				% (len(cnt_raw) + len(base_raw)))
		mml.NumberOfMemoryRanges = int.from_bytes(cnt_raw, byteorder = 'little', signed = False)
		mml.BaseRva = int.from_bytes(base_raw, byteorder = 'little', signed = False)
		available = None
		if hasattr(buff, 'getbuffer'):
			available = len(buff.getbuffer()) - buff.tell()
		elif hasattr(buff, 'file_size'):
			available = buff.file_size - buff.tell()
		if available is not None:
			validate_record_count(
				mml.NumberOfMemoryRanges,
				MINIDUMP_MEMORY_DESCRIPTOR64().get_size(),
				available, what='64-bit memory range')
		for _ in range(mml.NumberOfMemoryRanges):
			mml.MemoryRanges.append(MINIDUMP_MEMORY_DESCRIPTOR64.parse(buff))

		return mml

	def __str__(self):
		t  = '== MINIDUMP_MEMORY64_LIST ==\n'
		t += 'NumberOfMemoryRanges: %s\n' % self.NumberOfMemoryRanges
		t += 'BaseRva: %s\n' % self.BaseRva
		for i in range(self.NumberOfMemoryRanges):
			t += str(self.MemoryRanges[i]) + '\n'
		return t


# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680384(v=vs.85).aspx
class MINIDUMP_MEMORY_DESCRIPTOR64:
	def __init__(self):
		self.StartOfMemoryRange:int = None
		self.DataSize:int = None

	def get_size(self):
		return 16

	def to_bytes(self):
		t = self.StartOfMemoryRange.to_bytes(8, byteorder = 'little', signed = False)
		t += self.DataSize.to_bytes(8, byteorder = 'little', signed = False)
		return t

	@staticmethod
	def parse(buff):
		md = MINIDUMP_MEMORY_DESCRIPTOR64()
		start_raw = buff.read(8)
		size_raw = buff.read(8)
		if len(start_raw) != 8 or len(size_raw) != 8:
			raise MinidumpMalformedFileException(
				'Truncated MINIDUMP_MEMORY_DESCRIPTOR64: expected 16 bytes, got %d'
				% (len(start_raw) + len(size_raw)))
		md.StartOfMemoryRange = int.from_bytes(start_raw, byteorder = 'little', signed = False)
		md.DataSize = int.from_bytes(size_raw, byteorder = 'little', signed = False)
		return md

	def __str__(self):
		t = 'Start: %s' % hex(self.StartOfMemoryRange)
		t += 'Size: %s' % self.DataSize
		return t

class MinidumpMemory64List:
	def __init__(self):
		self.memory_segments:List[MinidumpMemorySegment] = []

	@staticmethod
	def parse(dir, buff):
		t = MinidumpMemory64List()
		buff.check_rva(dir.Location.Rva, dir.Location.DataSize, what='Memory64ListStream')
		chunk = StrictBytesIO(buff.read_range(
			dir.Location.Rva, dir.Location.DataSize, what='Memory64ListStream'))
		mtl = MINIDUMP_MEMORY64_LIST.parse(chunk)
		rva = mtl.BaseRva
		for mod in mtl.MemoryRanges:
			# Every memory region must actually exist in the file; a BaseRva
			# pointing past EOF is rejected instead of yielding empty bytes.
			buff.check_rva(rva, mod.DataSize, what='full-memory region data')
			t.memory_segments.append(MinidumpMemorySegment.parse_full(mod, rva))
			rva += mod.DataSize
		return t

	@staticmethod
	async def aparse(dir, buff):
		t = MinidumpMemory64List()
		buff.check_rva(dir.Location.Rva, dir.Location.DataSize, what='Memory64ListStream')
		chunk_data = await buff.read_range(
			dir.Location.Rva, dir.Location.DataSize, what='Memory64ListStream')
		chunk = StrictBytesIO(chunk_data)
		mtl = MINIDUMP_MEMORY64_LIST.parse(chunk)
		rva = mtl.BaseRva
		for mod in mtl.MemoryRanges:
			buff.check_rva(rva, mod.DataSize, what='full-memory region data')
			ms = MinidumpMemorySegment.parse_full(mod, rva)
			t.memory_segments.append(ms)
			rva += mod.DataSize
		return t

	def to_table(self):
		t = []
		t.append(MinidumpMemorySegment.get_header())
		for mod in self.memory_segments:
			t.append(mod.to_row())
		return t

	def __str__(self):
		return '== MinidumpMemory64List ==\n' + construct_table(self.to_table())
