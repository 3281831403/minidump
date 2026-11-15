#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import sys
import enum
import struct
import logging
from typing import List

from minidump.header import MinidumpHeader, HEADER_SIZE
from minidump.minidumpreader import MinidumpFileReader
from minidump.streams import *
from minidump.common_structs import *
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.directory import MINIDUMP_DIRECTORY
from minidump.exceptions import MinidumpBoundaryException, MinidumpStreamException, MinidumpException
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE
from minidump.structures.peb import PEB


class MinidumpFile:
	def __init__(self):
		self.filename:str = None
		self.file_handle = None
		self.file_size:int = 0
		self.header:MinidumpHeader = None
		self.directories: List[MINIDUMP_DIRECTORY] = []

		self.threads_ex:MinidumpThreadExList = None
		self.threads:MinidumpThreadList = None
		self.modules:MinidumpModuleList = None
		self.memory_segments:MinidumpMemoryList = None
		self.memory_segments_64:MinidumpMemory64List = None
		self.sysinfo:MinidumpSystemInfo = None
		self.comment_a:CommentStreamA = None
		self.comment_w:CommentStreamW = None
		self.exception:ExceptionList = None
		self.handles:MinidumpHandleDataStream = None
		self.unloaded_modules:MinidumpUnloadedModuleList = None
		self.misc_info:MinidumpMiscInfo = None
		self.memory_info:MinidumpMemoryInfoList = None
		self.thread_info:MinidumpThreadInfoList = None

		self.peb:PEB = None

	@staticmethod
	def parse(filename):
		mf = MinidumpFile()
		mf.filename = filename
		buffer = open(filename, 'rb')
		mf.file_size = MinidumpFile._measure(buffer)
		mf.file_handle = BoundedFileReader(buffer, mf.file_size)
		mf._parse()
		return mf

	@staticmethod
	def parse_external(file_handle, filename = ''):
		"""
		External file handle must be an object that exposes basic file IO functionality
		that you'd get by python's file buffer (read, seek, tell etc.)
		"""
		mf = MinidumpFile()
		mf.filename = filename
		mf.file_size = MinidumpFile._measure(file_handle)
		mf.file_handle = BoundedFileReader(file_handle, mf.file_size)
		mf._parse()
		return mf

	@staticmethod
	def parse_bytes(data):
		return MinidumpFile.parse_buff(io.BytesIO(data))

	@staticmethod
	def parse_buff(buffer):
		mf = MinidumpFile()
		mf.file_size = MinidumpFile._measure(buffer)
		mf.file_handle = BoundedFileReader(buffer, mf.file_size)
		mf._parse()
		return mf

	@staticmethod
	def _measure(buffer):
		pos = buffer.tell()
		buffer.seek(0, io.SEEK_END)
		size = buffer.tell()
		buffer.seek(pos, io.SEEK_SET)
		return size

	def get_reader(self):
		return MinidumpFileReader(self)

	def _parse(self):
		self.__parse_header()
		self.__parse_directories()
		try:
			self.__parse_peb()
		except MinidumpException:
			raise
		except Exception as e:
			logging.exception('PEB parsing error!')

	def __parse_header(self):
		self.header = MinidumpHeader.parse(self.file_handle)
		self.file_size = self.file_handle.file_size
		# The whole directory table must fit inside the file.
		dir_table_size = self.header.NumberOfStreams * 12
		self.file_handle.check_rva(
			self.header.StreamDirectoryRva, dir_table_size, what='stream directory table'
		)
		for i in range(0, self.header.NumberOfStreams):
			entry_rva = self.header.StreamDirectoryRva + i * 12
			self.file_handle.seek(entry_rva, 0)
			try:
				minidump_dir = MINIDUMP_DIRECTORY.parse(self.file_handle)
			except MinidumpException as e:
				raise type(e)(
					'%s (directory entry index %d at file offset 0x%x)'
					% (str(e), i, entry_rva)
				) from e

			if minidump_dir:
				self.directories.append(minidump_dir)
			else:
				logging.debug('Found Unknown UserStream directory at index %d', i)

	def _stream_dispatch_table(self):
		return {
			MINIDUMP_STREAM_TYPE.ThreadListStream:
				('threads', MinidumpThreadList.parse),
			MINIDUMP_STREAM_TYPE.ModuleListStream:
				('modules', MinidumpModuleList.parse),
			MINIDUMP_STREAM_TYPE.MemoryListStream:
				('memory_segments', MinidumpMemoryList.parse),
			MINIDUMP_STREAM_TYPE.ExceptionStream:
				('exception', ExceptionList.parse),
			MINIDUMP_STREAM_TYPE.SystemInfoStream:
				('sysinfo', MinidumpSystemInfo.parse),
			MINIDUMP_STREAM_TYPE.ThreadExListStream:
				('threads_ex', MinidumpThreadExList.parse),
			MINIDUMP_STREAM_TYPE.Memory64ListStream:
				('memory_segments_64', MinidumpMemory64List.parse),
			MINIDUMP_STREAM_TYPE.CommentStreamA:
				('comment_a', CommentStreamA.parse),
			MINIDUMP_STREAM_TYPE.CommentStreamW:
				('comment_w', CommentStreamW.parse),
			MINIDUMP_STREAM_TYPE.HandleDataStream:
				('handles', MinidumpHandleDataStream.parse),
			MINIDUMP_STREAM_TYPE.UnloadedModuleListStream:
				('unloaded_modules', MinidumpUnloadedModuleList.parse),
			MINIDUMP_STREAM_TYPE.MiscInfoStream:
				('misc_info', MinidumpMiscInfo.parse),
			MINIDUMP_STREAM_TYPE.MemoryInfoListStream:
				('memory_info', MinidumpMemoryInfoList.parse),
			MINIDUMP_STREAM_TYPE.ThreadInfoListStream:
				('thread_info', MinidumpThreadInfoList.parse),
		}

	def __parse_directories(self):
		dispatch = self._stream_dispatch_table()
		# Stream types that are defined by the format but intentionally not
		# implemented by this parser. They are ignored when their directory
		# location is within the file bounds.
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

			# Unknown stream type (raw integer, not a MINIDUMP_STREAM_TYPE).
			# Its directory location was already validated, so skip it.
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
				setattr(self, attr, parse_func(dir, self.file_handle))
			except MinidumpException as e:
				raise MinidumpStreamException(
					'Failed to parse stream %s (RVA 0x%x, declared size %d, file size 0x%x): %s'
					% (stream_type.name, dir.Location.Rva, dir.Location.DataSize,
					   self.file_size, e)
				) from e

		try:
			self.__parse_thread_context()
		except MinidumpException:
			raise
		except Exception as e:
			logging.exception('Thread context parsing error!')

	def __parse_thread_context(self):
		if not self.sysinfo or not self.threads:
			return
		for thread in self.threads.threads:
			rva = thread.ThreadContext.Rva
			self.file_handle.seek(rva)
			if self.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
				thread.ContextObject = CONTEXT.parse(self.file_handle)
			elif self.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
				thread.ContextObject = WOW64_CONTEXT.parse(self.file_handle)

	def __parse_peb(self):
		if not self.sysinfo or not self.threads:
			return
		
		self.peb = PEB.from_minidump(self)
		


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
				t+= str(segment) + '\n'

		if self.memory_segments_64 is not None:
			for segment in self.memory_segments_64.memory_segments:
				t+= str(segment) + '\n'

		return t
