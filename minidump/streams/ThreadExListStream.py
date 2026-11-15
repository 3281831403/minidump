#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
from minidump.common_structs import *
from minidump.exceptions import MinidumpBoundaryException, MinidumpMalformedFileException
from minidump.streams.MemoryListStream import MINIDUMP_MEMORY_DESCRIPTOR

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680399(v=vs.85).aspx
class MINIDUMP_THREAD_EX_LIST:
	def __init__(self):
		self.NumberOfThreads = None
		self.Threads = []

	@staticmethod
	def get_record_size():
		# MINIDUMP_THREAD (48) + extra BackingStore MINIDUMP_MEMORY_DESCRIPTOR (16)
		return 64

	@staticmethod
	def parse(buff):
		mtel = MINIDUMP_THREAD_EX_LIST()
		raw = buff.read(4)
		if len(raw) != 4:
			raise MinidumpMalformedFileException(
				'Truncated MINIDUMP_THREAD_EX_LIST: NumberOfThreads could not be read')
		mtel.NumberOfThreads = int.from_bytes(raw, byteorder = 'little', signed = False)
		available = None
		if hasattr(buff, 'getbuffer'):
			available = len(buff.getbuffer()) - buff.tell()
		elif hasattr(buff, 'file_size'):
			available = buff.file_size - buff.tell()
		if available is not None:
			validate_record_count(
				mtel.NumberOfThreads,
				MINIDUMP_THREAD_EX_LIST.get_record_size(),
				available, what='extended thread')
		for _ in range(mtel.NumberOfThreads):
			mtel.Threads.append(MINIDUMP_THREAD_EX.parse(buff))

		return mtel

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680400(v=vs.85).aspx
class MINIDUMP_THREAD_EX:
	def __init__(self):
		self.ThreadId = None
		self.SuspendCount = None
		self.PriorityClass = None
		self.Priority = None
		self.Teb = None
		self.Stack = None
		self.ThreadContext = None
		self.BackingStore = None

	@staticmethod
	def parse(buff):
		mte = MINIDUMP_THREAD_EX()
		mte.ThreadId = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mte.SuspendCount = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mte.PriorityClass = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mte.Priority = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mte.Teb = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		mte.Stack = MINIDUMP_MEMORY_DESCRIPTOR.parse(buff)
		mte.ThreadContext = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
		mte.BackingStore = MINIDUMP_MEMORY_DESCRIPTOR.parse(buff)
		return mte

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


class MinidumpThreadExList:
	def __init__(self):
		self.threads = []

	@staticmethod
	def parse(dir, buff):
		t = MinidumpThreadExList()
		buff.check_rva(dir.Location.Rva, dir.Location.DataSize, what='ThreadExListStream')
		chunk = StrictBytesIO(buff.read_range(
			dir.Location.Rva, dir.Location.DataSize, what='ThreadExListStream'))
		mtl = MINIDUMP_THREAD_EX_LIST.parse(chunk)
		t.threads = mtl.Threads
		return t

	@staticmethod
	async def aparse(dir, buff):
		t = MinidumpThreadExList()
		buff.check_rva(dir.Location.Rva, dir.Location.DataSize, what='ThreadExListStream')
		chunk_data = await buff.read_range(
			dir.Location.Rva, dir.Location.DataSize, what='ThreadExListStream')
		chunk = StrictBytesIO(chunk_data)
		mtl = MINIDUMP_THREAD_EX_LIST.parse(chunk)
		t.threads = mtl.Threads
		return t

	def to_table(self):
		t = []
		t.append(MINIDUMP_THREAD_EX.get_header())
		for thread in self.threads:
			t.append(thread.to_row())
		return t

	def __str__(self):
		return '== ThreadExList ==\n' + construct_table(self.to_table())
