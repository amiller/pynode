
#
# HeaderDb.py - Bitcoin blockchain database
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import string
import cStringIO
import leveldb
import io
import os
import time
from decimal import Decimal
from Cache import Cache
from bitcoin.serialize import *
from bitcoin.core import *
from bitcoin.messages import msg_block, message_to_str, message_read
from bitcoin.coredefs import COIN
from bitcoin.scripteval import VerifySignature



def tx_blk_cmp(a, b):
	if a.dFeePerKB != b.dFeePerKB:
		return int(a.dFeePerKB - b.dFeePerKB)
	return int(a.dPriority - b.dPriority)

def block_value(height, fees):
	subsidy = 50 * COIN
	subsidy >>= (height / 210000)
	return subsidy + fees

class TxIdx(object):
	def __init__(self, blkhash=0L, spentmask=0L):
		self.blkhash = blkhash
		self.spentmask = spentmask


class BlkMeta(object):
	def __init__(self):
		self.height = -1
		self.work = 0L

	def deserialize(self, s):
		l = s.split()
		if len(l) < 2:
			raise RuntimeError
		self.height = int(l[0])
		self.work = long(l[1], 16)

	def serialize(self):
		r = str(self.height) + ' ' + hex(self.work)
		return r

	def __repr__(self):
		return "BlkMeta(height %d, work %x)" % (self.height, self.work)


class HeightIdx(object):
	def __init__(self):
		self.blocks = []

	def deserialize(self, s):
		self.blocks = []
		l = s.split()
		for hashstr in l:
			hash = long(hashstr, 16)
			self.blocks.append(hash)

	def serialize(self):
		l = []
		for blkhash in self.blocks:
			l.append(hex(blkhash))
		return ' '.join(l)

	def __repr__(self):
		return "HeightIdx(blocks=%s)" % (self.serialize(),)


class HeaderDb(object):
	def __init__(self, settings, datadir, log, mempool, netmagic,
		     readonly=False, fast_dbm=False):
		self.settings = settings
		self.log = log
		self.mempool = mempool
		self.readonly = readonly
		self.netmagic = netmagic
		self.fast_dbm = fast_dbm
		self.blk_cache = Cache(500)
		self.orphans = {}
		self.orphan_deps = {}

		# LevelDB to hold:
		#    misc:*    state
		#    height:*  list of blocks at height h
		#    blkmeta:* block metadata
		self.db = leveldb.LevelDB(datadir + '/headerdb')

		try:
			self.db.Get('misc:height')
		except KeyError:
			self.log.write("INITIALIZING EMPTY BLOCKCHAIN DATABASE")
			batch = leveldb.WriteBatch()
			batch.Put('misc:height', str(-1))
			batch.Put('misc:msg_start', self.netmagic.msg_start)
			batch.Put('misc:tophash', ser_uint256(0L))
			batch.Put('misc:total_work', hex(0L))
			self.db.Write(batch)

		try:
			start = self.db.Get('misc:msg_start')
			if start != self.netmagic.msg_start: raise KeyError
		except KeyError:
			self.log.write("Database magic number mismatch. Data corruption or incorrect network?")
			raise RuntimeError

	def haveblock(self, blkhash, checkorphans):
		if self.blk_cache.exists(blkhash):
			return True
		if checkorphans and blkhash in self.orphans:
			return True
		ser_hash = ser_uint256(blkhash)
		try: 
			self.db.Get('blkmeta:'+ser_hash)
			return True
		except KeyError:
			return False

	def have_prevblock(self, block):
		if self.getheight() < 0 and block.sha256 == self.netmagic.block0:
			return True
		if self.haveblock(block.hashPrevBlock, False):
			return True
		return False

	def connect_block(self, ser_hash, block, blkmeta):
		# verify against checkpoint list
		try:
			chk_hash = self.netmagic.checkpoints[blkmeta.height]
			if chk_hash != block.sha256:
				self.log.write("Block %064x does not match checkpoint hash %064x, height %d" % (
					block.sha256, chk_hash, blkmeta.height))
				return False
		except KeyError:
			pass

		# update database pointers for best chain
		batch = leveldb.WriteBatch()
		batch.Put('misc:total_work', hex(blkmeta.work))
		batch.Put('misc:height', str(blkmeta.height))
		batch.Put('misc:tophash', ser_hash)

		self.log.write("HeaderDb: height %d, block %064x" % (
				blkmeta.height, block.sha256))

		self.db.Write(batch)
		return True

	def disconnect_block(self, block):
		ser_prevhash = ser_uint256(block.hashPrevBlock)
		prevmeta = BlkMeta()
		prevmeta.deserialize(self.db.Get('blkmeta:'+ser_prevhash))

		batch = leveldb.WriteBatch()
		for outpt in outpts:
			self.clear_txout(outpt[0], outpt[1], batch)

		# update database pointers for best chain
		batch.Put('misc:total_work', hex(prevmeta.work))
		batch.Put('misc:height', str(prevmeta.height))
		batch.Put('misc:tophash', ser_prevhash)
		self.db.Write(batch)

		self.log.write("ChainDb(disconn): height %d, block %064x" % (
				prevmeta.height, block.hashPrevBlock))

		return True

	def getblockmeta(self, blkhash):
		ser_hash = ser_uint256(blkhash)
		try:
			meta = BlkMeta()
			meta.deserialize(self.db.Get('blkmeta:'+ser_hash))
		except KeyError:
			return None

		return meta
	
	def getblockheight(self, blkhash):
		meta = self.getblockmeta(blkhash)
		if meta is None:
			return -1

		return meta.height

	def reorganize(self, new_best_blkhash):
		self.log.write("REORGANIZE")

		conn = []
		disconn = []

		old_best_blkhash = self.gettophash()
		fork = old_best_blkhash
		longer = new_best_blkhash
		while fork != longer:
			while (self.getblockheight(longer) >
			       self.getblockheight(fork)):
				block = self.getblock(longer)
				block.calc_sha256()
				conn.append(block)

				longer = block.hashPrevBlock
				if longer == 0:
					return False

			if fork == longer:
				break

			block = self.getblock(fork)
			block.calc_sha256()
			disconn.append(block)

			fork = block.hashPrevBlock
			if fork == 0:
				return False

		self.log.write("REORG disconnecting top hash %064x" % (old_best_blkhash,))
		self.log.write("REORG connecting new top hash %064x" % (new_best_blkhash,))
		self.log.write("REORG chain union point %064x" % (fork,))
		self.log.write("REORG disconnecting %d blocks, connecting %d blocks" % (len(disconn), len(conn)))

		for block in disconn:
			if not self.disconnect_block(block):
				return False

		for block in conn:
			if not self.connect_block(ser_uint256(block.sha256),
				  block, self.getblockmeta(block.sha256)):
				return False

		self.log.write("REORGANIZE DONE")
		return True

	def set_best_chain(self, ser_prevhash, ser_hash, block, blkmeta):
		# the easy case, extending current best chain
		if (blkmeta.height == 0 or
		    self.db.Get('misc:tophash') == ser_prevhash):
			return self.connect_block(ser_hash, block, blkmeta)

		# switching from current chain to another, stronger chain
		return self.reorganize(block.sha256)

	def putoneblock(self, block):
		block.calc_sha256()

		if not block.is_valid_spv():
			self.log.write("Invalid block %064x" % (block.sha256, ))
			return False

		if not self.have_prevblock(block):
			self.orphans[block.sha256] = True
			self.orphan_deps[block.hashPrevBlock] = block
			self.log.write("Orphan block %064x (%d orphans)" % (block.sha256, len(self.orphan_deps)))
			return False

		top_height = self.getheight()
		top_work = long(self.db.Get('misc:total_work'), 16)

		# read metadata for previous block
		prevmeta = BlkMeta()
		if top_height >= 0:
			ser_prevhash = ser_uint256(block.hashPrevBlock)
			prevmeta.deserialize(self.db.Get('blkmeta:'+ser_prevhash))
		else:
			ser_prevhash = ''

		batch = leveldb.WriteBatch()

		# build network "block" msg, as canonical disk storage form
		msg = msg_block()
		msg.block = block
		msg_data = message_to_str(self.netmagic, msg)

		# write "block" msg to storage
		#fpos = self.blk_write.tell()
		#self.blk_write.write(msg_data)
		#self.blk_write.flush()
                fpos = -1

                # write
		self.blk_cache.put(block.sha256, block)

		# add index entry
		ser_hash = ser_uint256(block.sha256)
		batch.Put('blocks:'+ser_hash, str(fpos))

		# store metadata related to this block
		blkmeta = BlkMeta()
		blkmeta.height = prevmeta.height + 1
		blkmeta.work = (prevmeta.work +
				uint256_from_compact(block.nBits))
		batch.Put('blkmeta:'+ser_hash, blkmeta.serialize())

		# store list of blocks at this height
		heightidx = HeightIdx()
		heightstr = str(blkmeta.height)
		try:
			heightidx.deserialize(self.db.Get('height:'+heightstr))
		except KeyError:
			pass
		heightidx.blocks.append(block.sha256)

		batch.Put('height:'+heightstr, heightidx.serialize())
		self.db.Write(batch)

		# if chain is not best chain, proceed no further
		if (blkmeta.work <= top_work):
			self.log.write("ChainDb: height %d (weak), block %064x" % (blkmeta.height, block.sha256))
			return True

		# update global chain pointers
		if not self.set_best_chain(ser_prevhash, ser_hash,
					   block, blkmeta):
			return False

		return True

	def putblock(self, block):
		block.calc_sha256()
		if self.haveblock(block.sha256, True):
			self.log.write("Duplicate block %064x submitted" % (block.sha256, ))
			return False

		if not self.putoneblock(block):
			return False

		blkhash = block.sha256
		while blkhash in self.orphan_deps:
			block = self.orphan_deps[blkhash]
			if not self.putoneblock(block):
				return True

			del self.orphan_deps[blkhash]
			del self.orphans[block.sha256]

			blkhash = block.sha256

		return True

	def locate(self, locator):
		for hash in locator.vHave:
			ser_hash = ser_uint256(hash)
			if ser_hash in self.blkmeta:
				blkmeta = BlkMeta()
				blkmeta.deserialize(self.db.Get('blkmeta:'+ser_hash))
				return blkmeta
		return 0

	def getheight(self):
		return int(self.db.Get('misc:height'))

	def gettophash(self):
		return uint256_from_str(self.db.Get('misc:tophash'))

	def loadfile(self, filename):
		fd = os.open(filename, os.O_RDONLY)
		self.log.write("IMPORTING DATA FROM " + filename)
		buf = ''
		wanted = 4096
		while True:
			if wanted > 0:
				if wanted < 4096:
					wanted = 4096
				s = os.read(fd, wanted)
				if len(s) == 0:
					break

				buf += s
				wanted = 0

			buflen = len(buf)
			startpos = string.find(buf, self.netmagic.msg_start)
			if startpos < 0:
				wanted = 8
				continue

			sizepos = startpos + 4
			blkpos = startpos + 8
			if blkpos > buflen:
				wanted = 8
				continue

			blksize = struct.unpack("<i", buf[sizepos:blkpos])[0]
			if (blkpos + blksize) > buflen:
				wanted = 8 + blksize
				continue

			ser_blk = buf[blkpos:blkpos+blksize]
			buf = buf[blkpos+blksize:]

			f = cStringIO.StringIO(ser_blk)
			block = CBlock()
			block.deserialize(f)

			self.putblock(block)
