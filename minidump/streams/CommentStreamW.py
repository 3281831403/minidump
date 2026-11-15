#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
from minidump.common_structs import StrictBytesIO

class CommentStreamW:
	def __init__(self):
		self.data:str = None

	def to_bytes(self):
		return self.data.encode('utf-16-le')

	@staticmethod
	def parse(dir, buff):
		csa = CommentStreamW()
		buff.check_rva(dir.Location.Rva, dir.Location.DataSize, what='CommentStreamW')
		csa.data = buff.read_range(
			dir.Location.Rva, dir.Location.DataSize, what='CommentStreamW').decode('utf-16-le')
		return csa

	@staticmethod
	async def aparse(dir, buff):
		csa = CommentStreamW()
		buff.check_rva(dir.Location.Rva, dir.Location.DataSize, what='CommentStreamW')
		csdata = await buff.read_range(
			dir.Location.Rva, dir.Location.DataSize, what='CommentStreamW')
		csa.data = csdata.decode('utf-16-le')
		return csa

	def __str__(self):
		return 'CommentW: %s' % self.data
