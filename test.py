from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import toml
import numpy as np

configs = toml.load('/client/config.toml')
print(configs)

BYTES_NUMBER = configs['types']['BYTES_NUMBER']
MASK_TYPE = configs['types']['MASK_TYPE']
MODEL_LEN = configs['types']['MODEL_LEN']

def create_mask(peerpubkey, seckey):
    # We are going to use AES in CTR mode as a pseudo random generator
    # to generate Puv 
    # CTR is configured with full zero nounce
    # AES will encrypt full zero plaintext every time but using different key
    ctr = modes.CTR(b'\x00' * 16)
    initialPlaintext = b'\x00' * BYTES_NUMBER * MODEL_LEN 


    publicKey = serialization.load_pem_public_key(peerpubkey, default_backend())
    # Create shared key
    sharedKey = seckey.exchange(ec.ECDH(), publicKey)
    # Perform key derivation
    derivedKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend()
    ).derive(sharedKey)

    # **** COMPUTE Puv (client shared mask)
    cipherPuv = Cipher(algorithms.AES(derivedKey), ctr, backend=default_backend())
    encryptor = cipherPuv.encryptor()

    # Generate random bytes to fill Puv array
    ct = encryptor.update(initialPlaintext) + encryptor.finalize()

    # Convert random bytes to a numpy array
    puv = np.frombuffer(ct, dtype=np.dtype(MASK_TYPE))
    puv = puv.astype('float64')

    return puv



def main():

    CuSK = ec.generate_private_key(
        ec.SECP384R1(),
        default_backend())
    CuPK = CuSK.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


    SuSK = ec.generate_private_key(
        ec.SECP384R1(),
        default_backend())
    SuPK = SuSK.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    SuSK_serialized = SuSK.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    for loc in range(80, len(SuSK_serialized)-100):
        v = SuSK_serialized[loc]
        v+=1
        v = v.to_bytes(1, "big")
        editable_sk = SuSK_serialized[:loc]+v+SuSK_serialized[loc+1:]
        try:
            SuSK_new = serialization.load_pem_private_key(
                editable_sk, 
                None, default_backend())
        except ValueError:
            print("changing bit {} in sk failed".format(loc))
            continue
        else:
            print("changing bit {} in sk".format(loc))
            break
    else:
        print("didn't find a bit I can change in sk :(")
        sys.exit(1)

    SuSK_new_serialized = SuSK_new.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    #print(SuSK_serialized == SuSK_serialized)
    #print(SuSK_new_serialized == SuSK_serialized)
    #print(SuSK_new_serialized)
    #print(SuSK_serialized)


    puv1 = create_mask(CuPK, SuSK)
    puv2 = create_mask(CuPK, SuSK_new)
    #print(puv1-puv2)
    #np.save(open('mask_'+str(MODEL_LEN)+'_'+str(MASK_TYPE)+'.npy', 'wb'), puv1-puv2)
    np.save(open('mask.npy', 'wb'), puv1-puv2)
    print('wrote diff in file')
    

if __name__ == "__main__":
    main()
