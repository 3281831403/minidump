#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
from minidump.common_structs import *
from minidump.exceptions import MinidumpBoundaryException, MinidumpMalformedFileException
from minidump.streams.MemoryListStream import MINIDUMP_MEMORY_DESCRIPTOR

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680515(v=vs.85).aspx
class MINIDUMP_THREAD_LIST:
	def __init__(self):
		self.NumberOfThreads = None
		self.Threads = []

	def to_bytes(self):
		t = len(self.Threads).to_bytes(4, byteorder = 'little', signed = False)
		for th in self.Threads:
			t += th.to_bytes()
		return t

	@staticmethod
	def get_record_size():
		# 4+4+4+4 + 8 (header) + 16 (MINIDUMP_MEMORY_DESCRIPTOR) + 8 (location descriptor)
		return 48

	@staticmethod
	def parse(buff):
		mtl = MINIDUMP_THREAD_LIST()
		raw = buff.read(4)
		if len(raw) != 4:
			raise MinidumpMalformedFileException(
				'Truncated MINIDUMP_THREAD_LIST: NumberOfThreads could not be read')
		mtl.NumberOfThreads = int.from_bytes(raw, byteorder = 'little', signed = False)
		available = None
		if hasattr(buff, 'getbuffer'):
			available = len(buff.getbuffer()) - buff.tell()
		elif hasattr(buff, 'file_size'):
			available = buff.file_size - buff.tell()
		if available is not None:
			validate_record_count(
				mtl.NumberOfThreads,
				MINIDUMP_THREAD_LIST.get_record_size(),
				available, what='thread')
		for _ in range(mtl.NumberOfThreads):
			mtl.Threads.append(MINIDUMP_THREAD.parse(buff))
		return mtl

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680517(v=vs.85).aspx
class MINIDUMP_THREAD:
	def __init__(self):
		self.ThreadId = None
		self.SuspendCount = None
		self.PriorityClass = None
		self.Priority = None
		self.Teb = None
		self.Stack = None
		self.ThreadContext = None

	def to_bytes(self):
		t  = self.ThreadId.value.to_bytes(4, byteorder = 'little', signed = False)
		t += self.SuspendCount.to_bytes(4, byteorder = 'little', signed = False)
		t += self.PriorityClass.to_bytes(4, byteorder = 'little', signed = False)
		t += self.Priority.to_bytes(4, byteorder = 'little', signed = False)
		t += self.Teb.to_bytes(8, byteorder = 'little', signed = False)
		t += self.Stack.to_bytes()
		t += self.ThreadContext.to_bytes()
		return t

	@staticmethod
	def parse(buff):
		mt = MINIDUMP_THREAD()
		mt.ThreadId = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mt.SuspendCount = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mt.PriorityClass = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mt.Priority = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mt.Teb = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		mt.Stack = MINIDUMP_MEMORY_DESCRIPTOR.parse(buff)
		mt.ThreadContext = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)

		return mt

	@staticmethod
	def get_header():
		return [
			'ThreadId',
			'SuspendCount',
			'PriorityClass',
			'Priority',
			'Teb',
			#'Stack',
			#'ThreadContext',
		]

	def to_row(self):
		return [
			hex(self.ThreadId),
			str(self.SuspendCount),
			str(self.PriorityClass),
			str(self.Priority),
			hex(self.Teb),
			#self.Stack,
			#self.ThreadContext,
		]

class MinidumpThreadList:
	def __init__(self):
		self.threads = []

	@staticmethod
	def parse(dir, buff):
		t = MinidumpThreadList()
		buff.check_rva(dir.Location.Rva, dir.Location.DataSize, what='ThreadListStream')
		chunk = StrictBytesIO(buff.read_range(
			dir.Location.Rva, dir.Location.DataSize, what='ThreadListStream'))
		mtl = MINIDUMP_THREAD_LIST.parse(chunk)
		t.threads = mtl.Threads
		return t

	@staticmethod
	async def aparse(dir, buff):
		t = MinidumpThreadList()
		buff.check_rva(dir.Location.Rva, dir.Location.DataSize, what='ThreadListStream')
		chunk_data = await buff.read_range(
			dir.Location.Rva, dir.Location.DataSize, what='ThreadListStream')
		chunk = StrictBytesIO(chunk_data)
		mtl = MINIDUMP_THREAD_LIST.parse(chunk)
		t.threads = mtl.Threads
		return t

	def to_table(self):
		t = []
		t.append(MINIDUMP_THREAD.get_header())
		for thread in self.threads:
			t.append(thread.to_row())
		return t

	def __str__(self):
		return 'ThreadList\n' + construct_table(self.to_table())