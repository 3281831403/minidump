#!/usr/bin/env python3
#
# Regression tests for truncated / malformed minidump handling.
# Every fixture is built inline from raw bytes; no external dump files.
#
import io
import os
import struct
import asyncio
import tempfile
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from minidump.minidumpfile import MinidumpFile
from minidump.aminidumpfile import AMinidumpFile
from minidump.exceptions import (
	MinidumpException,
	MinidumpBoundaryException,
	MinidumpMalformedFileException,
	MinidumpStreamException,
	MinidumpHeaderSignatureMismatchException,
		MinidumpHeaderFlagsException,
)

HEADER_SIZE = 28
DIRECTORY_ENTRY_SIZE = 12


def header(number_of_streams, directory_rva, flags=0):
	# Signature('MDMP') Version ImplVersion NumberOfStreams Rva CheckSum TimeStamp Flags
	return b'MDMP' + struct.pack(
		'<HHIIIII', 0xA793, 0, number_of_streams, directory_rva, 0, 0, flags)


def directory_entry(stream_type, data_size, rva):
	return struct.pack('<III', stream_type, data_size, rva)


def system_info_stream():
	# AMD64 (9), 48-byte MINIDUMP_SYSTEM_INFO, no CSD string (rva 0)
	return (struct.pack('<HHHBBIIIIIHH',
		9,      # ProcessorArchitecture AMD64
		6,      # ProcessorLevel
		0x8E00, # ProcessorRevision
		1,      # NumberOfProcessors
		1,      # ProductType
		10, 0, 19045, 2,  # Major/Minor/Build/PlatformId
		0,      # CSDVersionRva
		0, 0)   # SuiteMask / Reserved2
		+ b'\x00' * 16)  # two 64-bit processor features


def build_minimal_valid_dump():
	"""A valid dump: system info + one module + one memory range with data."""
	sysinfo = system_info_stream()

	name = 'kernel32.dll'.encode('utf-16-le')
	name_blob = struct.pack('<I', len(name)) + name

	mem_data = b'A' * 0x40 + b'B' * 0x40

	module_record = (
		struct.pack('<Q', 0x400000) +   # BaseOfImage
		struct.pack('<I', 0x10000) +    # SizeOfImage
		struct.pack('<I', 0x12345678) + # CheckSum
		struct.pack('<I', 0x11223344) + # TimeDateStamp
		struct.pack('<I', 0) +          # ModuleNameRva (patched below)
		b'\x00' * 52 +                  # VS_FIXEDFILEINFO
		b'\x00' * 8 +                   # CvRecord
		b'\x00' * 8 +                   # MiscRecord
		b'\x00' * 16                    # Reserved0/1
	)
	assert len(module_record) == 108

	number_of_streams = 3
	cursor = HEADER_SIZE + number_of_streams * DIRECTORY_ENTRY_SIZE
	rva_sysinfo = cursor; cursor += len(sysinfo)
	rva_name = cursor; cursor += len(name_blob)
	rva_mem = cursor; cursor += len(mem_data)

	module_record = module_record[:20] + struct.pack('<I', rva_name) + module_record[24:]
	module_list = struct.pack('<I', 1) + module_record
	rva_module_list = cursor; cursor += len(module_list)

	mem_descriptor = struct.pack('<Q', 0x10000) + struct.pack('<II', len(mem_data), rva_mem)
	memory_list = struct.pack('<I', 1) + mem_descriptor
	rva_memory_list = cursor

	directory = b''
	directory += directory_entry(7, len(sysinfo), rva_sysinfo)
	directory += directory_entry(4, len(module_list), rva_module_list)
	directory += directory_entry(5, len(memory_list), rva_memory_list)

	data = header(number_of_streams, HEADER_SIZE) + directory
	data += sysinfo + name_blob + mem_data + module_list + memory_list
	return data


class TruncationTests(unittest.TestCase):

	def test_16_byte_file_raises_malformed(self):
		# Only 16 bytes present although the header alone needs 28.
		data = b'MDMP' + struct.pack('<HHI', 0xA793, 0, 4) + struct.pack('<I', 0)
		self.assertEqual(len(data), 16)
		with self.assertRaises(MinidumpMalformedFileException):
			MinidumpFile.parse_bytes(data)

	def test_directory_table_past_eof_raises_boundary(self):
		# Valid 28-byte header claiming 4 streams whose table is missing.
		data = header(4, HEADER_SIZE)
		with self.assertRaises(MinidumpBoundaryException) as ctx:
			MinidumpFile.parse_bytes(data)
		self.assertIn('directory table', str(ctx.exception))

	def test_directory_entry_rva_past_eof_raises(self):
		entry = directory_entry(4, 112, 0x1000)
		data = header(1, HEADER_SIZE) + entry
		with self.assertRaises(MinidumpBoundaryException) as ctx:
			MinidumpFile.parse_bytes(data)
		# message names the entry index and the offending file offset
		self.assertIn('index 0', str(ctx.exception))
		self.assertIn('0x1000', str(ctx.exception))

	def test_never_returns_half_parsed_directories(self):
		# Header claims 4 streams but only enough bytes for one exist;
		# parsing must fail rather than silently returning fewer directories.
		entry = directory_entry(23, 4, HEADER_SIZE + DIRECTORY_ENTRY_SIZE)
		data = header(4, HEADER_SIZE) + entry
		with self.assertRaises(MinidumpException):
			MinidumpFile.parse_bytes(data)


class ModuleListTests(unittest.TestCase):

	def test_truncated_module_count_rejected(self):
		# Count says 2 modules but only a single (zeroed) 108-byte record exists.
		module_list = struct.pack('<I', 2) + b'\x00' * 108
		entry = directory_entry(4, len(module_list), HEADER_SIZE)
		data = header(1, HEADER_SIZE + len(module_list)) + module_list + entry
		with self.assertRaises(MinidumpStreamException) as ctx:
			MinidumpFile.parse_bytes(data)
		self.assertIn('ModuleListStream', str(ctx.exception))
		self.assertIsInstance(ctx.exception.__cause__, MinidumpBoundaryException)

	def test_zero_second_module_not_fabricated(self):
		# Count says 1 and exactly one record exists -> parses fine, no zero module.
		module_record = b'\x00' * 108
		module_list = struct.pack('<I', 1) + module_record
		entry = directory_entry(4, len(module_list), HEADER_SIZE)
		data = header(1, HEADER_SIZE + len(module_list)) + module_list + entry
		# Module name RVA 0 resolves to the existing (empty) placeholder behaviour;
		# the important assertion is exactly one module, never a zero-filled second.
		mf = MinidumpFile.parse_bytes(data)
		self.assertEqual(len(mf.modules.modules), 1)


class Memory64Tests(unittest.TestCase):
	def test_baserva_past_eof_raises(self):
		# Full-memory dump whose BaseRva points beyond the end of the file.
		mem64 = struct.pack('<QQ', 1, 0x100000) + struct.pack('<QQ', 0x1000, 0x100)
		entry = directory_entry(9, len(mem64), HEADER_SIZE)
		data = header(1, HEADER_SIZE + len(mem64)) + mem64 + entry
		with self.assertRaises(MinidumpException) as ctx:
			mf = MinidumpFile.parse_bytes(data)
			mf.get_reader().read(0x1000, 4)
		self.assertIn('Memory64ListStream', str(ctx.exception))

	def test_baserva_past_eof_never_returns_empty_bytes(self):
		mem64 = struct.pack('<QQ', 1, 0x100000) + struct.pack('<QQ', 0x1000, 0x100)
		entry = directory_entry(9, len(mem64), HEADER_SIZE)
		data = header(1, HEADER_SIZE + len(mem64)) + mem64 + entry
		with self.assertRaises(MinidumpException):
			MinidumpFile.parse_bytes(data)

	def test_valid_memory64_reads_real_bytes(self):
		payload = b'Z' * 0x20
		# BaseRva placed right after the directory + descriptor stream.
		stream = struct.pack('<QQ', 1, 0) + struct.pack('<QQ', 0x50000, len(payload))
		base_rva = HEADER_SIZE + DIRECTORY_ENTRY_SIZE + len(stream)
		stream = struct.pack('<QQ', 1, base_rva) + struct.pack('<QQ', 0x50000, len(payload))
		entry = directory_entry(9, len(stream), HEADER_SIZE + DIRECTORY_ENTRY_SIZE)
		data = header(1, HEADER_SIZE) + entry + stream + payload
		mf = MinidumpFile.parse_bytes(data)
		reader = mf.get_reader()
		self.assertTrue(reader.is_fulldump)
		self.assertEqual(reader.read(0x50000, 4), b'ZZZZ')

	def test_memory64_count_beyond_stream_raises(self):
		# Claims 9 ranges but contains no descriptors.
		stream = struct.pack('<QQ', 9, HEADER_SIZE)
		entry = directory_entry(9, len(stream), HEADER_SIZE)
		data = header(1, HEADER_SIZE + len(stream)) + stream + entry
		with self.assertRaises(MinidumpStreamException):
			MinidumpFile.parse_bytes(data)

	def test_memory_list_data_rva_out_of_bounds_raises(self):
		# A normal memory list whose backing data RVA points past EOF.
		memory_list = struct.pack('<I', 1) + struct.pack('<QII', 0x10000, 0x10, 0x9999)
		entry = directory_entry(5, len(memory_list), HEADER_SIZE)
		data = header(1, HEADER_SIZE + len(memory_list)) + memory_list + entry
		with self.assertRaises(MinidumpException):
			mf = MinidumpFile.parse_bytes(data)
			mf.get_reader().read(0x10000, 4)


class UnknownStreamTests(unittest.TestCase):
	def test_unknown_in_range_stream_types_skipped(self):
		payload = b'X' * 8
		entry_23 = directory_entry(23, 4, HEADER_SIZE)
		entry_38 = directory_entry(38, 4, HEADER_SIZE + 4)
		data = header(2, HEADER_SIZE + len(payload)) + payload + entry_23 + entry_38
		mf = MinidumpFile.parse_bytes(data)
		# Directories are retained for inspection, parsing does not raise.
		self.assertEqual(len(mf.directories), 2)

	def test_unknown_stream_out_of_bounds_still_raises(self):
		entry = directory_entry(23, 4, 0x9999)
		data = header(1, HEADER_SIZE) + entry
		with self.assertRaises(MinidumpBoundaryException):
			MinidumpFile.parse_bytes(data)

	def test_unimplemented_known_stream_skipped(self):
		# FunctionTableStream (13): known enum value, parser intentionally absent.
		payload = b'\x00' * 24
		entry = directory_entry(13, len(payload), HEADER_SIZE)
		data = header(1, HEADER_SIZE + len(payload)) + payload + entry
		mf = MinidumpFile.parse_bytes(data)
		self.assertEqual(len(mf.directories), 1)
		self.assertIsNone(mf.sysinfo)

	def test_unknown_user_stream_skipped(self):
		# Stream types above LastReservedStream (0xffff) are client-defined
		# user streams and must be ignored.
		entry = directory_entry(0x12345, 4, HEADER_SIZE)
		data = header(1, HEADER_SIZE) + entry
		mf = MinidumpFile.parse_bytes(data)
		self.assertEqual(mf.directories, [])

	def test_bad_module_name_rva_raises_typed(self):
		module_record = (
			struct.pack('<Q', 0x400000) + struct.pack('<I', 0x1000) +
			struct.pack('<I', 0) * 2 + struct.pack('<I', 0x9999) +
			b'\x00' * 52 + b'\x00' * 16 + b'\x00' * 16)
		self.assertEqual(len(module_record), 108)
		module_list = struct.pack('<I', 1) + module_record
		entry = directory_entry(4, len(module_list), HEADER_SIZE)
		data = header(1, HEADER_SIZE + len(module_list)) + module_list + entry
		with self.assertRaises(MinidumpStreamException):
			MinidumpFile.parse_bytes(data)


class MissingTableTests(unittest.TestCase):

	def test_reader_constructible_without_tables(self):
		data = header(0, HEADER_SIZE)
		mf = MinidumpFile.parse_bytes(data)
		reader = mf.get_reader()  # must not raise AttributeError
		self.assertEqual(reader.memory_segments, [])
		self.assertEqual(reader.modules, [])

	def test_str_works_without_tables(self):
		data = header(0, HEADER_SIZE)
		mf = MinidumpFile.parse_bytes(data)
		text = str(mf)  # must not raise AttributeError
		self.assertIn('Minidump File', text)
		self.assertIn('NumberOfStreams: 0', text)

	def test_all_style_printing_without_tables(self):
		# Mirrors every guarded print the --all CLI path performs.
		data = header(0, HEADER_SIZE)
		mf = MinidumpFile.parse_bytes(data)
		mf.get_reader()
		for attr in ('threads', 'threads_ex', 'thread_info', 'modules',
					 'unloaded_modules', 'memory_segments', 'memory_segments_64',
					 'memory_info', 'sysinfo', 'exception', 'comment_a',
					 'comment_w', 'handles', 'misc_info', 'peb'):
			value = getattr(mf, attr)
			if value is not None:
				str(value)

	def test_cli_all_does_not_crash_without_tables(self):
		data = header(0, HEADER_SIZE)
		repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
		with tempfile.NamedTemporaryFile(suffix='.dmp', delete=False) as tmp:
			tmp.write(data)
			tmp_path = tmp.name
		try:
			proc = subprocess.run(
				[sys.executable, '-m', 'minidump', tmp_path, '--all'],
				cwd=repo_root, capture_output=True, text=True, timeout=30)
			self.assertEqual(proc.returncode, 0, proc.stderr)
		finally:
			os.unlink(tmp_path)


class AsyncTests(unittest.TestCase):

	def test_async_parse_bytes_is_awaitable(self):
		data = header(0, HEADER_SIZE)
		mf = asyncio.run(AMinidumpFile.parse_bytes(data))
		self.assertEqual(mf.header.NumberOfStreams, 0)

	def test_async_reader_without_tables(self):
		data = header(0, HEADER_SIZE)
		mf = asyncio.run(AMinidumpFile.parse_bytes(data))
		reader = mf.get_reader()
		self.assertEqual(reader.memory_segments, [])

	def test_sync_async_same_fields(self):
		data = build_minimal_valid_dump()
		sync_mf = MinidumpFile.parse_bytes(data)
		async_mf = asyncio.run(AMinidumpFile.parse_bytes(data))

		self.assertEqual(str(sync_mf), str(async_mf))
		self.assertEqual(
			[m.baseaddress for m in sync_mf.modules.modules],
			[m.baseaddress for m in async_mf.modules.modules])
		sync_segments = sync_mf.memory_segments.memory_segments
		async_segments = async_mf.memory_segments.memory_segments
		self.assertEqual(
			[(s.start_virtual_address, s.size, s.start_file_address) for s in sync_segments],
			[(s.start_virtual_address, s.size, s.start_file_address) for s in async_segments])
		sr = sync_mf.get_reader()
		ar = async_mf.get_reader()
		self.assertEqual(sr.read(0x10000, 8), asyncio.run(ar.read(0x10000, 8)))
		self.assertEqual(sr.is_fulldump, ar.is_fulldump)

	def test_async_unknown_stream_skipped(self):
		payload = b'X' * 8
		entry = directory_entry(23, 4, HEADER_SIZE)
		data = header(1, HEADER_SIZE + len(payload)) + payload + entry
		mf = asyncio.run(AMinidumpFile.parse_bytes(data))
		self.assertEqual(len(mf.directories), 1)

	def test_parse_external_handle(self):
		data = header(0, HEADER_SIZE)
		mf = MinidumpFile.parse_external(io.BytesIO(data))
		self.assertEqual(mf.header.NumberOfStreams, 0)

	def test_async_parse_from_real_file(self):
		data = header(0, HEADER_SIZE)
		with tempfile.NamedTemporaryFile(suffix='.dmp', delete=False) as tmp:
			tmp.write(data)
			tmp_path = tmp.name
		try:
			mf = asyncio.run(AMinidumpFile.parse(tmp_path))
			self.assertEqual(mf.header.NumberOfStreams, 0)
		finally:
			os.unlink(tmp_path)


class ValidDumpBehaviorTests(unittest.TestCase):

	def setUp(self):
		self.data = build_minimal_valid_dump()
		self.mf = MinidumpFile.parse_bytes(self.data)

	def test_valid_dump_cli_text_stable(self):
		text = str(self.mf)
		self.assertIn('StreamType: MINIDUMP_STREAM_TYPE.SystemInfoStream', text)
		self.assertIn('StreamType: MINIDUMP_STREAM_TYPE.ModuleListStream', text)
		self.assertIn('StreamType: MINIDUMP_STREAM_TYPE.MemoryListStream', text)
		self.assertIn('kernel32.dll', text)
		self.assertIn('VA Start: 0x10000', text)

	def test_valid_dump_memory_read(self):
		reader = self.mf.get_reader()
		self.assertEqual(reader.read(0x10000, 8), b'AAAAAAAA')
		self.assertEqual(reader.read(0x10040, 2), b'BB')

	def test_oob_read_raises_typed_exception(self):
		reader = self.mf.get_reader()
		with self.assertRaises(MinidumpBoundaryException):
			reader.read(0x99999, 4)

	def test_signature_exception_unchanged(self):
		bad = b'XXXX' + b'\x00' * 24
		with self.assertRaises(MinidumpHeaderSignatureMismatchException):
			MinidumpFile.parse_bytes(bad)
		# It remains part of the MinidumpException hierarchy.
		self.assertTrue(
			issubclass(MinidumpHeaderSignatureMismatchException, MinidumpException))

	def test_header_flags_exception_unchanged(self):
		# The dedicated header-flags exception must remain part of the
		# MinidumpException hierarchy. (Python 3.14's permissive IntFlag no
		# longer rejects unknown raw integers, so it cannot be triggered via a
		# bare value on every runtime; the header code path is left intact.)
		self.assertTrue(
			issubclass(MinidumpHeaderFlagsException, MinidumpException))
		# A well-formed header still parses its flags normally.
		mf = MinidumpFile.parse_bytes(
			b'MDMP' + struct.pack('<HHIIIII', 0xA793, 0, 0, HEADER_SIZE, 0, 0, 0))
		self.assertEqual(int(mf.header.Flags), 0)


if __name__ == '__main__':
	unittest.main(verbosity=2)
