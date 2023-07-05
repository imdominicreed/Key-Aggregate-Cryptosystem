
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,extract_key
# from charm.core.math.integer import *
from charm.core.engine.util import objectToBytes,bytesToObject,serializeObject

from Crypto.Cipher import AES

class KAC:

	def __init__(self, groupObj='SS512'):
		self.n = None
		self.e_g1_g2 = None
		global group
		group = PairingGroup(groupObj)
		self.group = group
		global size
		size = len(extract_key(group.random(GT)))

	def setup(self, n, file_name=None, save_name=None):
		self.n = n
		if file_name==None:
			a = group.random(ZR)
			param = [group.random(G1)]
			assert param[0].initPP(), "failed to init pre-computation table"
			for i in range(1, (2 * self.n)+1):
				param.append(param[0] ** (a ** i))
			if save_name != None:
				f = open("mine.param", "wb")
				for p in param:
					f.write(group.serialize(p, compression=False) +b'\n')
		else:
			print('reading', file_name)
			f = open(file_name, "rb")
			param = []
			for line in f:
				param.append(group.deserialize(line))

		self.e_g1_g2 = pair(param[1], param[n])
		assert self.e_g1_g2.initPP(), "failed to init pre-computation table"
		return param

	def keygen(self, param):
		y = group.random(ZR)
		pk = param[0] ** y
		return pk,y

	def encrypt(self, pk, i, m, param):
		t = group.random(ZR)
	

		p = group.random(GT)
		aes = AES.new(extract_key(p))

		return (param[0] ** t, (pk * param[i]) ** t, p * (self.e_g1_g2 ** t) , aes.encrypt(self._pad(m)))

	def extract(self, msk, S, param):
		K_s = group.init(G1, 1)
		for i in S:
			K_s *= param[self.n+1-i]
		K_s = K_s ** msk
		return K_s

		#msk = y


	def decrypt(self, K_s, S, i, ct, param):
		aggregate1 = group.init(G1, 1)
		aggregate2 = group.init(G1, 1)
		result = None

		if i in S:
			for j in S:
				if j!=i:
					aggregate1 *= param[self.n+1-j+i]
				aggregate2 *= param[self.n+1-j]

			key = ct[2] * pair(K_s * aggregate1, ct[0]) / pair(aggregate2, ct[1])
			extract_key(key)
			aes = AES.new(extract_key(key))
			result = self._unpad(aes.decrypt(ct[3]))

		return result
	
	def _pad(self, s):
		return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

	def _unpad(self, s):
		return s[:-ord(s[len(s)-1:])]

kac = KAC()
param = kac.setup(100)

pk, msk = kac.keygen(param)
c = kac.encrypt(pk, 1, "Today is a very good day!", param)

s = [i for i in range(1,100)]
key = kac.extract( msk, s, param)


print(kac.decrypt(key,s,1, c,param ))









