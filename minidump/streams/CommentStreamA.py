#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
from minidump.common_structs import StrictBytesIO

class CommentStreamA:
	def __init__(self):
		self.data:str = None

	def to_bytes(self):
		return self.data.encode('ascii')

	@staticmethod
	def parse(dir, buff):
		csa = CommentStreamA()
		buff.check_rva(dir.Location.Rva, dir.Location.DataSize, what='CommentStreamA')
		csa.data = buff.read_range(
			dir.Location.Rva, dir.Location.DataSize, what='CommentStreamA').decode()
		return csa

	@staticmethod
	async def aparse(dir, buff):
		csa = CommentStreamA()
		buff.check_rva(dir.Location.Rva, dir.Location.DataSize, what='CommentStreamA')
		csdata = await buff.read_range(
			dir.Location.Rva, dir.Location.DataSize, what='CommentStreamA')
		csa.data = csdata.decode()
		return csa

	def __str__(self):
		return 'CommentA: %s' % self.data
