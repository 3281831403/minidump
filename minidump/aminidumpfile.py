#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import logging

from minidump.header import MinidumpHeader
from minidump.aminidumpreader import AMinidumpFileReader
from minidump.streams import *
from minidump.common_structs import (
	AsyncBoundedFileReader, StrictBytesIO,
)
from minidump.exceptions import MinidumpBoundaryException, MinidumpStreamException, MinidumpException
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.directory import MINIDUMP_DIRECTORY


class AsyncFile:
	def __init__(self, filename):
		self.filename = filename
		self.fhandle = open(filename, 'rb')

	async def read(self, n = -1):
		return self.fhandle.read(n)

	async def seek(self, n, beg = 0):
		return self.fhandle.seek(n, beg)

	def tell(self):
		return self.fhandle.tell()


class AsyncBuffer:
	"""Async adapter around a plain synchronous buffer (e.g. io.BytesIO)."""
	def __init__(self, buffer):
		self.buffer = buffer

	async def read(self, n = -1):
		return self.buffer.read(n)

	async def seek(self, n, beg = 0):
		return self.buffer.seek(n, beg)

	def tell(self):
		return self.buffer.tell()

class AMinidumpFile:
	def __init__(self):
		self.filename = None
		self.file_handle = None
		self.file_size = 0
		self.header = None
		self.directories = []

		self.threads_ex = None
		self.threads = None
		self.modules = None
		self.memory_segments = None
		self.memory_segments_64 = None
		self.sysinfo = None
		self.comment_a = None
		self.comment_w = None
		self.exception = None
		self.handles = None
		self.unloaded_modules = None
		self.misc_info = None
		self.memory_info = None
		self.thread_info = None
		self.peb = None

	@staticmethod
	async def parse(filename):
		mf = AMinidumpFile()
		mf.filename = filename
		mf.file_handle = AsyncFile(filename)
		mf.file_size = await mf._measure(mf.file_handle)
		mf.file_handle = AsyncBoundedFileReader(mf.file_handle, mf.file_size)
		await mf._parse()
		return mf

	@staticmethod
	async def parse_external(file_handle, filename = ''):
		"""
		External file handle must be an object that exposes basic file IO functionality
		that you'd get by python's file buffer (read, seek, tell etc.)
		"""
		mf = AMinidumpFile()
		mf.filename = filename
		mf.file_handle = file_handle
		mf.file_size = await mf._measure(mf.file_handle)
		mf.file_handle = AsyncBoundedFileReader(file_handle, mf.file_size)
		await mf._parse()
		return mf

	@staticmethod
	async def parse_bytes(data):
		return await AMinidumpFile.parse_buff(AsyncBuffer(io.BytesIO(data)))

	@staticmethod
	async def parse_buff(buffer):
		mf = AMinidumpFile()
		mf.file_size = await mf._measure(buffer)
		mf.file_handle = AsyncBoundedFileReader(buffer, mf.file_size)
		await mf._parse()
		return mf

	@staticmethod
	async def _measure(buffer):
		pos = buffer.tell()
		await buffer.seek(0, io.SEEK_END)
		size = buffer.tell()
		await buffer.seek(pos, io.SEEK_SET)
		return size

	def get_reader(self):
		return AMinidumpFileReader(self)

	def _stream_dispatch_table(self):
		return {
			MINIDUMP_STREAM_TYPE.ThreadListStream:
				('threads', MinidumpThreadList.aparse),
			MINIDUMP_STREAM_TYPE.ModuleListStream:
				('modules', MinidumpModuleList.aparse),
			MINIDUMP_STREAM_TYPE.MemoryListStream:
				('memory_segments', MinidumpMemoryList.aparse),
			MINIDUMP_STREAM_TYPE.ExceptionStream:
				('exception', ExceptionList.aparse),
			MINIDUMP_STREAM_TYPE.SystemInfoStream:
				('sysinfo', MinidumpSystemInfo.aparse),
			MINIDUMP_STREAM_TYPE.ThreadExListStream:
				('threads_ex', MinidumpThreadExList.aparse),
			MINIDUMP_STREAM_TYPE.Memory64ListStream:
				('memory_segments_64', MinidumpMemory64List.aparse),
			MINIDUMP_STREAM_TYPE.CommentStreamA:
				('comment_a', CommentStreamA.aparse),
			MINIDUMP_STREAM_TYPE.CommentStreamW:
				('comment_w', CommentStreamW.aparse),
			MINIDUMP_STREAM_TYPE.HandleDataStream:
				('handles', MinidumpHandleDataStream.aparse),
			MINIDUMP_STREAM_TYPE.UnloadedModuleListStream:
				('unloaded_modules', MinidumpUnloadedModuleList.aparse),
			MINIDUMP_STREAM_TYPE.MiscInfoStream:
				('misc_info', MinidumpMiscInfo.aparse),
			MINIDUMP_STREAM_TYPE.MemoryInfoListStream:
				('memory_info', MinidumpMemoryInfoList.aparse),
			MINIDUMP_STREAM_TYPE.ThreadInfoListStream:
				('thread_info', MinidumpThreadInfoList.aparse),
		}

	async def _parse(self):
		await self.__parse_header()
		await self.__parse_directories()

	async def __parse_header(self):
		self.header = await MinidumpHeader.aparse(self.file_handle)
		# The whole directory table must fit inside the file.
		dir_table_size = self.header.NumberOfStreams * 12
		self.file_handle.check_rva(
			self.header.StreamDirectoryRva, dir_table_size, what='stream directory table'
		)
		for i in range(0, self.header.NumberOfStreams):
			entry_rva = self.header.StreamDirectoryRva + i * 12
			await self.file_handle.seek(entry_rva, 0)
			try:
				minidump_dir = await MINIDUMP_DIRECTORY.aparse(self.file_handle)
			except MinidumpException as e:
				raise type(e)(
					'%s (directory entry index %d at file offset 0x%x)'
					% (str(e), i, entry_rva)
				) from e

			if minidump_dir:
				self.directories.append(minidump_dir)
			else:
				logging.debug('Found Unknown UserStream directory at index %d', i)

	async def __parse_directories(self):
		dispatch = self._stream_dispatch_table()
		ignored_types = {
			MINIDUMP_STREAM_TYPE.UnusedStream,
			MINIDUMP_STREAM_TYPE.ReservedStream0,
			MINIDUMP_STREAM_TYPE.ReservedStream1,
			MINIDUMP_STREAM_TYPE.FunctionTableStream,
			MINIDUMP_STREAM_TYPE.SystemMemoryInfoStream,
			MINIDUMP_STREAM_TYPE.JavaScriptDataStream,
			MINIDUMP_STREAM_TYPE.ProcessVmCountersStream,
			MINIDUMP_STREAM_TYPE.TokenStream,
			MINIDUMP_STREAM_TYPE.HandleOperationListStream,
			MINIDUMP_STREAM_TYPE.ThreadNamesStream,
		}

		for dir in self.directories:
			stream_type = dir.StreamType

			if not isinstance(stream_type, MINIDUMP_STREAM_TYPE):
				logging.debug(
					'Skipping unknown stream type %s at RVA 0x%x, size %d',
					stream_type, dir.Location.Rva, dir.Location.DataSize)
				continue

			if stream_type in ignored_types:
				logging.debug(
					'Ignoring stream %s at RVA 0x%x, size %d (reserved or not implemented)',
					stream_type.name, dir.Location.Rva, dir.Location.DataSize)
				continue

			handler = dispatch.get(stream_type)
			if handler is None:
				logging.debug(
					'Skipping unsupported stream %s at RVA 0x%x, size %d',
					stream_type.name, dir.Location.Rva, dir.Location.DataSize)
				continue

			attr, parse_func = handler
			try:
				setattr(self, attr, await parse_func(dir, self.file_handle))
			except MinidumpException as e:
				raise MinidumpStreamException(
					'Failed to parse stream %s (RVA 0x%x, declared size %d, file size 0x%x): %s'
					% (stream_type.name, dir.Location.Rva, dir.Location.DataSize,
					   self.file_size, e)
				) from e

	def __str__(self):
		t = '== Minidump File ==\n'
		if self.header is not None:
			t += str(self.header)
		if self.sysinfo is not None:
			t += str(self.sysinfo)
		for dir in self.directories:
			t += str(dir) + '\n'
		if self.modules is not None:
			for mod in self.modules.modules:
				t += str(mod) + '\n'

		if self.memory_segments is not None:
			for segment in self.memory_segments.memory_segments:
				t += str(segment) + '\n'

		if self.memory_segments_64 is not None:
			for segment in self.memory_segments_64.memory_segments:
				t += str(segment) + '\n'

		return t
