package openssl

// #include "shim.h"
import "C"

func EvpBytesToKey(blocksize int, digest EVP_MD, salt string, data string, count int) (int, []byte, []byte) {
	cipher, err := getGCMCipher(blocksize)
	if err != nil {
		return 0, nil, nil
	}
	var sptr *C.uchar
	if len(salt) > 0 {
		sptr = (*C.uchar)(&[]byte(salt)[0])
	} else {
		sptr = (*C.uchar)(nil)
	}
	kptr := (*C.uchar)(&[]byte(data)[0])

	key := make([]byte, 64)
	keyPtr := (*C.uchar)(&key[0])
	iv := make([]byte, 16)
	ivPtr := (*C.uchar)(&iv[0])
	ret := C.EVP_BytesToKey(
		cipher.ptr,
		getDigestFunction(digest),
		sptr,
		kptr,
		C.int(len(data)),
		C.int(count),
		keyPtr,
		ivPtr)
	return int(ret), key, iv
}
