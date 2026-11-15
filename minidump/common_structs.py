import io

from minidump.exceptions import MinidumpBoundaryException, MinidumpMalformedFileException


class StrictBytesIO(io.BytesIO):
	"""
	BytesIO that refuses to silently return a short (possibly zero-filled)
	read. Every read that returns fewer bytes than asked for raises
	MinidumpMalformedFileException instead.
	"""
	def read(self, size=-1):
		if size is None or size < 0:
			return super().read(size)
		data = super().read(size)
		if len(data) != size:
			raise MinidumpMalformedFileException(
				'Truncated minidump data: expected %d bytes at offset %d but only %d were available'
				% (size, self.tell() - len(data), len(data))
			)
		return data


class BoundedFileReader:
	"""
	File-like wrapper that knows the total size of the underlying data and
	can validate RVAs / ranges before they are used. Reads past the end of
	the file raise MinidumpBoundaryException or MinidumpMalformedFileException.
	"""
	def __init__(self, file_handle, file_size):
		self.file_handle = file_handle
		self.file_size = file_size

	def _check_range(self, offset, size, what='data'):
		if offset is None or offset < 0:
			raise MinidumpBoundaryException('Invalid %s offset: %s' % (what, offset))
		if offset > self.file_size:
			raise MinidumpBoundaryException(
				'%s offset 0x%x points past end of file (file size 0x%x)'
				% (what.capitalize(), offset, self.file_size)
			)
		if size < 0:
			raise MinidumpBoundaryException('Invalid %s size: %d' % (what, size))
		if offset + size > self.file_size:
			raise MinidumpBoundaryException(
				'%s range [0x%x + 0x%x = 0x%x] exceeds end of file (file size 0x%x)'
				% (what.capitalize(), offset, size, offset + size, self.file_size)
			)

	def check_rva(self, rva, size=0, what='stream'):
		self._check_range(rva, size, what)

	def tell(self):
		return self.file_handle.tell()

	def seek(self, offset, whence=0):
		return self.file_handle.seek(offset, whence)

	def read(self, size=-1):
		return self.file_handle.read(size)

	def read_range(self, offset, size, what='stream'):
		self._check_range(offset, size, what)
		pos = self.file_handle.tell()
		self.file_handle.seek(offset, 0)
		data = self.file_handle.read(size)
		self.file_handle.seek(pos, 0)
		if len(data) != size:
			raise MinidumpMalformedFileException(
				'Truncated %s at offset 0x%x: expected %d bytes, got %d'
				% (what, offset, size, len(data))
			)
		return data


class AsyncBoundedFileReader:
	"""Async counterpart of BoundedFileReader."""
	def __init__(self, file_handle, file_size):
		self.file_handle = file_handle
		self.file_size = file_size

	def _check_range(self, offset, size, what='data'):
		if offset is None or offset < 0:
			raise MinidumpBoundaryException('Invalid %s offset: %s' % (what, offset))
		if offset > self.file_size:
			raise MinidumpBoundaryException(
				'%s offset 0x%x points past end of file (file size 0x%x)'
				% (what.capitalize(), offset, self.file_size)
			)
		if size < 0:
			raise MinidumpBoundaryException('Invalid %s size: %d' % (what, size))
		if offset + size > self.file_size:
			raise MinidumpBoundaryException(
				'%s range [0x%x + 0x%x = 0x%x] exceeds end of file (file size 0x%x)'
				% (what.capitalize(), offset, size, offset + size, self.file_size)
			)

	def check_rva(self, rva, size=0, what='stream'):
		self._check_range(rva, size, what)

	def tell(self):
		return self.file_handle.tell()

	async def seek(self, offset, whence=0):
		return await self.file_handle.seek(offset, whence)

	async def read(self, size=-1):
		return await self.file_handle.read(size)

	async def read_range(self, offset, size, what='stream'):
		self._check_range(offset, size, what)
		pos = self.file_handle.tell()
		await self.file_handle.seek(offset, 0)
		data = await self.file_handle.read(size)
		await self.file_handle.seek(pos, 0)
		if len(data) != size:
			raise MinidumpMalformedFileException(
				'Truncated %s at offset 0x%x: expected %d bytes, got %d'
				% (what, offset, size, len(data))
			)
		return data


def validate_record_count(count, record_size, available_size, what='record'):
	"""
	Verify that `count` fixed-size records of `record_size` bytes each fit
	into the `available_size` bytes of the enclosing stream. Rejects
	descriptor counts that point beyond the stream data instead of
	silently manufacturing zero-filled records.
	"""
	if count < 0:
		raise MinidumpBoundaryException('Invalid negative %s count: %d' % (what, count))
	if record_size <= 0:
		raise MinidumpBoundaryException('Invalid %s size: %d' % (what, record_size))
	needed = count * record_size
	if needed > available_size:
		raise MinidumpBoundaryException(
			'%s count %d requires %d bytes but only %d bytes are available in the stream'
			% (what.capitalize(), count, needed, available_size)
		)


# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680383(v=vs.85).aspx
class MINIDUMP_LOCATION_DESCRIPTOR:
	def __init__(self):
		self.DataSize = None
		self.Rva = None

	def get_size(self):
		return 8

	def to_bytes(self):
		t = self.DataSize.to_bytes(4, byteorder = 'little', signed = False)
		t += self.Rva.to_bytes(4, byteorder = 'little', signed = False)
		return t

	@staticmethod
	def parse(buff):
		mld = MINIDUMP_LOCATION_DESCRIPTOR()
		size_raw = buff.read(4)
		rva_raw = buff.read(4)
		if len(size_raw) != 4 or len(rva_raw) != 4:
			raise MinidumpMalformedFileException(
				'Truncated MINIDUMP_LOCATION_DESCRIPTOR: expected 8 bytes but only %d were available'
				% (len(size_raw) + len(rva_raw)))
		mld.DataSize = int.from_bytes(size_raw, byteorder = 'little', signed = False)
		mld.Rva = int.from_bytes(rva_raw, byteorder = 'little', signed = False)
		return mld

	@staticmethod
	async def aparse(buff):
		mld = MINIDUMP_LOCATION_DESCRIPTOR()
		size_raw = await buff.read(4)
		rva_raw = await buff.read(4)
		if len(size_raw) != 4 or len(rva_raw) != 4:
			raise MinidumpMalformedFileException(
				'Truncated MINIDUMP_LOCATION_DESCRIPTOR: expected 8 bytes but only %d were available'
				% (len(size_raw) + len(rva_raw)))
		mld.DataSize = int.from_bytes(size_raw, byteorder = 'little', signed = False)
		mld.Rva = int.from_bytes(rva_raw, byteorder = 'little', signed = False)
		return mld

	def __str__(self):
		t = 'Size: %s File offset: %s' % (self.DataSize, self.Rva)
		return t

class MINIDUMP_LOCATION_DESCRIPTOR64:
	def __init__(self):
		self.DataSize = None
		self.Rva = None

	def get_size(self):
		return 16

	def to_bytes(self):
		t = self.DataSize.to_bytes(8, byteorder = 'little', signed = False)
		t += self.Rva.to_bytes(8, byteorder = 'little', signed = False)
		return t

	@staticmethod
	def parse(buff):
		mld = MINIDUMP_LOCATION_DESCRIPTOR64()
		mld.DataSize = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		mld.Rva = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		return mld

	def __str__(self):
		t = 'Size: %s File offset: %s' % (self.DataSize, self.Rva)
		return t

class MINIDUMP_STRING:
	def __init__(self):
		self.Length = None
		self.Buffer = None

	@staticmethod
	def parse(buff):
		ms = MINIDUMP_STRING()
		ms.Length = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		ms.Buffer = buff.read(ms.Length)
		return ms

	@staticmethod
	async def aparse(buff):
		ms = MINIDUMP_STRING()
		t = await buff.read(4)
		ms.Length = int.from_bytes(t, byteorder = 'little', signed = False)
		ms.Buffer = await buff.read(ms.Length)
		return ms

	@staticmethod
	def get_from_rva(rva, buff):
		pos = buff.tell()
		check_rva = getattr(buff, 'check_rva', None)
		if check_rva is not None:
			check_rva(rva, 0, what='MINIDUMP_STRING')
		buff.seek(rva, 0)
		ms = MINIDUMP_STRING.parse(buff)
		buff.seek(pos, 0)
		try:
			return ms.Buffer.decode('utf-16-le')
		except:
			return '<STRING_DECODE_FAILED>'

	@staticmethod
	async def aget_from_rva(rva, buff):
		pos = buff.tell()
		check_rva = getattr(buff, 'check_rva', None)
		if check_rva is not None:
			check_rva(rva, 0, what='MINIDUMP_STRING')
		await buff.seek(rva, 0)
		ms = await MINIDUMP_STRING.aparse(buff)
		await buff.seek(pos, 0)
		try:
			return ms.Buffer.decode('utf-16-le')
		except:
			return '<STRING_DECODE_FAILED>'

class MinidumpMemorySegment:
	def __init__(self):
		self.start_virtual_address = None
		self.size = None
		self.end_virtual_address = None
		self.start_file_address = None

	@staticmethod
	def parse_mini(memory_decriptor, buff):
		"""
		memory_descriptor: MINIDUMP_MEMORY_DESCRIPTOR
		buff: file_handle
		"""
		mms = MinidumpMemorySegment()
		mms.start_virtual_address = memory_decriptor.StartOfMemoryRange
		mms.size = memory_decriptor.DataSize
		mms.start_file_address = memory_decriptor.Rva
		mms.end_virtual_address = mms.start_virtual_address + mms.size
		return mms

	@staticmethod
	def parse_full(memory_decriptor, rva):
		mms = MinidumpMemorySegment()
		mms.start_virtual_address = memory_decriptor.StartOfMemoryRange
		mms.size = memory_decriptor.DataSize
		mms.start_file_address = rva
		mms.end_virtual_address = mms.start_virtual_address + mms.size
		return mms

	def inrange(self, virt_addr):
		if virt_addr >= self.start_virtual_address and virt_addr < self.end_virtual_address:
			return True
		return False

	def read(self, virtual_address, size, file_handler):
		if virtual_address > self.end_virtual_address or virtual_address < self.start_virtual_address:
			raise MinidumpBoundaryException('Reading from wrong segment! Virtual address 0x%x is not inside [0x%x, 0x%x)' % (virtual_address, self.start_virtual_address, self.end_virtual_address))

		if virtual_address+size > self.end_virtual_address:
			raise MinidumpBoundaryException('Read would cross boundaries!')

		pos = file_handler.tell()
		offset = virtual_address - self.start_virtual_address
		file_offset = self.start_file_address + offset
		check_rva = getattr(file_handler, 'check_rva', None)
		if check_rva is not None:
			check_rva(file_offset, size, what='memory segment data')
		file_handler.seek(file_offset, 0)
		data = file_handler.read(size)
		file_handler.seek(pos, 0)
		if len(data) != size:
			raise MinidumpMalformedFileException(
				'Truncated memory segment read at file offset 0x%x: expected %d bytes, got %d'
				% (file_offset, size, len(data))
			)
		return data

	async def aread(self, virtual_address, size, file_handler):
		if virtual_address > self.end_virtual_address or virtual_address < self.start_virtual_address:
			raise MinidumpBoundaryException('Reading from wrong segment! Virtual address 0x%x is not inside [0x%x, 0x%x)' % (virtual_address, self.start_virtual_address, self.end_virtual_address))

		if virtual_address+size > self.end_virtual_address:
			raise MinidumpBoundaryException('Read would cross boundaries!')

		pos = file_handler.tell()
		offset = virtual_address - self.start_virtual_address
		file_offset = self.start_file_address + offset
		check_rva = getattr(file_handler, 'check_rva', None)
		if check_rva is not None:
			check_rva(file_offset, size, what='memory segment data')
		await file_handler.seek(file_offset, 0)
		data = await file_handler.read(size)
		await file_handler.seek(pos, 0)
		if len(data) != size:
			raise MinidumpMalformedFileException(
				'Truncated memory segment read at file offset 0x%x: expected %d bytes, got %d'
				% (file_offset, size, len(data))
			)
		return data

	def search(self, pattern, file_handler, find_first = False, chunksize = 50*1024):
		if len(pattern) > self.size:
			return []
		pos = file_handler.tell()
		file_handler.seek(self.start_file_address, 0)
		fl = []
		if find_first is True:
			chunksize = min(chunksize, self.size)
			data = b''
			i = 0
			while len(data) < self.size:
				i += 1
				if chunksize > (self.size - len(data)):
					chunksize = (self.size - len(data))
				data += file_handler.read(chunksize)
				marker = data.find(pattern)
				if marker != -1:
					#print('FOUND! size: %s i: %s read: %s perc: %s' % (self.size, i, i*chunksize, 100*((i*chunksize)/self.size)))
					file_handler.seek(pos, 0)
					return [self.start_virtual_address + marker]


			#print('NOTFOUND! size: %s i: %s read: %s perc %s' % (self.size, i, len(data), 100*(len(data)/self.size) ))

		else:
			data = file_handler.read(self.size)
			file_handler.seek(pos, 0)

			offset = 0
			while len(data) > len(pattern):
				marker = data.find(pattern)
				if marker == -1:
					return fl
				fl.append(marker + offset + self.start_virtual_address)
				data = data[marker+1:]
				offset += marker + 1
				if find_first is True:
					return fl

		file_handler.seek(pos, 0)
		return fl

	async def asearch(self, pattern, file_handler, find_first = False, chunksize = 50*1024):
		if len(pattern) > self.size:
			return []
		pos = file_handler.tell()
		await file_handler.seek(self.start_file_address, 0)
		fl = []

		if find_first is True:
			chunksize = min(chunksize, self.size)
			data = b''
			i = 0
			while len(data) < self.size:
				i += 1
				if chunksize > (self.size - len(data)):
					chunksize = (self.size - len(data))
				data += await file_handler.read(chunksize)
				marker = data.find(pattern)
				if marker != -1:
					#print('FOUND! size: %s i: %s read: %s perc: %s' % (self.size, i, i*chunksize, 100*((i*chunksize)/self.size)))
					await file_handler.seek(pos, 0)
					return [self.start_virtual_address + marker]


			#print('NOTFOUND! size: %s i: %s read: %s perc %s' % (self.size, i, len(data), 100*(len(data)/self.size) ))

		else:
			offset = 0
			data = await file_handler.read(self.size)
			await file_handler.seek(pos, 0)
			while len(data) > len(pattern):
				marker = data.find(pattern)
				if marker == -1:
					return fl
				fl.append(marker + offset + self.start_virtual_address)
				data = data[marker+1:]
				offset += marker + 1
				if find_first is True:
					return fl

		await file_handler.seek(pos, 0)
		return fl


	@staticmethod
	def get_header():
		t = [
			'VA Start',
			'RVA',
			'Size',
		]
		return t

	def to_row(self):
		t = [
			hex(self.start_virtual_address),
			hex(self.start_file_address),
			hex(self.size)
		]
		return t

	def __str__(self):
		t = 'VA Start: %s, RVA: %s, Size: %s' % (hex(self.start_virtual_address), hex(self.start_file_address), hex(self.size))
		return t



def hexdump( src, length=16, sep='.', start = 0):
	'''
	@brief Return {src} in hex dump.
	@param[in] length	{Int} Nb Bytes by row.
	@param[in] sep		{Char} For the text part, {sep} will be used for non ASCII char.
	@return {Str} The hexdump

	@note Full support for python2 and python3 !
	'''
	result = [];

	# Python3 support
	try:
		xrange(0,1);
	except NameError:
		xrange = range;

	for i in xrange(0, len(src), length):
		subSrc = src[i:i+length];
		hexa = '';
		isMiddle = False;
		for h in xrange(0,len(subSrc)):
			if h == length/2:
				hexa += ' ';
			h = subSrc[h];
			if not isinstance(h, int):
				h = ord(h);
			h = hex(h).replace('0x','');
			if len(h) == 1:
				h = '0'+h;
			hexa += h+' ';
		hexa = hexa.strip(' ');
		text = '';
		for c in subSrc:
			if not isinstance(c, int):
				c = ord(c);
			if 0x20 <= c < 0x7F:
				text += chr(c);
			else:
				text += sep;
		if start == 0:
			result.append(('%08x:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i, hexa, text));
		else:
			result.append(('%08x(+%04x):  %-'+str(length*(2+1)+1)+'s  |%s|') % (start+i, i, hexa, text));
	return '\n'.join(result);

def construct_table(lines, separate_head=True):
	"""Prints a formatted table given a 2 dimensional array"""
	#Count the column width
	widths = []
	for line in lines:
			for i,size in enumerate([len(x) for x in line]):
					while i >= len(widths):
							widths.append(0)
					if size > widths[i]:
							widths[i] = size

	#Generate the format string to pad the columns
	print_string = ""
	for i,width in enumerate(widths):
			print_string += "{" + str(i) + ":" + str(width) + "} | "
	if (len(print_string) == 0):
			return
	print_string = print_string[:-3]

	#Print the actual data
	t = ''
	for i,line in enumerate(lines):
			t += print_string.format(*line) + '\n'
			if (i == 0 and separate_head):
					t += "-"*(sum(widths)+3*(len(widths)-1)) + '\n'

	return t
