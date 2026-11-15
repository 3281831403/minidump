
class MinidumpException(Exception):
	"""Generic Exception from minidump module"""
	pass

class MinidumpHeaderSignatureMismatchException(MinidumpException):
	"""Header signature was not correct"""
	pass

class MinidumpHeaderFlagsException(MinidumpException):
	"""Header flags value was not correct"""
	pass

class MinidumpMalformedFileException(MinidumpException):
	"""
	The minidump data is truncated or otherwise malformed: a fixed-size
	record could not be read in full, so no partial or zero-filled record
	is ever returned to the caller.
	"""
	pass

class MinidumpBoundaryException(MinidumpException):
	"""
	An RVA, a directory table or a descriptor count points outside the
	actual file data. The error message names the offending stream and
	the offsets involved.
	"""
	pass

class MinidumpStreamException(MinidumpException):
	"""
	A specific stream could not be parsed. The stream type, its RVA and
	its declared size are included in the error message.
	"""
	pass
