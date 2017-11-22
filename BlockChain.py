import des

def str_to_bitarray(s):
    # Converts string to a bit array.
    bitArr = list()
    for byte in s:
        bits = bin(byte)[2:] if isinstance(byte, int) else bin(ord(byte))[2:]
        while len(bits) < 8:
            bits = "0"+bits  # Add additional 0's as needed
        for bit in bits:
            bitArr.append(int(bit))
    return(bitArr)

def bitarray_to_str(bitArr):
    # Converts bit array to string
    result = ''
    for i in range(0,len(bitArr),8):
        byte = bitArr[i:i+8]
        s = ''.join([str(b) for b in byte])
        result = result+chr(int(s,2))
    return result

def xor(a, b):
    # xor function - This function is complete
    return [i^j for i,j in zip(a,b)]

def VernamEncrypt(binKey,block):
    # Vernam cipher
    if (len(binKey) != len(block)):
        raise Exception("Key is not same size as block")
    return xor(binKey,block)

def VernamDecrypt(binKey,block):
    # Basically a Vernam cipher.  Note it is
    # exactly the same as encryption.
    return VernamEncrypt(binKey,block)

class BlockChain():

    # Modes
    CBC = 0
    PCBC = 1
    CFB = 2
    
    def __init__(self,keyStr,ivStr,encryptMethod,decryptMethod,mode):
        self.encryptBlk = encryptMethod
        self.decryptBlk = decryptMethod
        self.key=keyStr
        self.iv=ivStr
        self.mode = mode
        self.flag=0             # to raise a flag when there is padding
        # Any other variables you might need

    def encrypt(self,msgs):
        # Returns a list of cipher blocks. These blocks are
        # generated based on the mode. The message may need
        # to be padded if not a multiple of 8 bytes (64 bits).
        
        #IV xor plaintext and encrypt
        cipherblks=[]
        if len(self.key)!= len(self.iv):
            print("iv not equal to key")
            exit
        size=len(self.key)
        msg=[] ; msg_bitarray=[] 
        while msgs:                     #list of msgs with size of each equal to key size
            msg.append(msgs[:size])
            msgs=msgs[size:]            
        for i in msg:
            msg_bitarray.append(str_to_bitarray(i))
        self.key_bitarray=str_to_bitarray(self.key)
        self.iv_bitarray=str_to_bitarray(self.iv)
        iv=self.iv_bitarray
        
        #performing padding
        
        first_len= len(msg_bitarray[0])
        last_len= len(msg_bitarray[-1])
        dif=bin(int((first_len-last_len)/8))[2:]
        while len(dif)<8:
            dif='0'+dif
        dif=[int(a) for a in dif]    
        while first_len-len(dif) > last_len :
            msg_bitarray[-1].insert(last_len,0)
            last_len= len(msg_bitarray[-1])
            self.flag=1
        msg_bitarray[-1].extend(dif)
        
        # Mode 0 - CBC ; Mode 1 - PCBC ; Mode 2 - CFB
        
        if self.mode == 0:
            print("\n\t======Vernam Encryption CBC=====\n")
            for a in msg_bitarray:
                Encrpty_out=d.decrypt(self.key_bitarray,iv)
                print("DES",Encrpty_out)
                
                
                Encrpty_out=VernamEncrypt(self.key_bitarray,iv)
                xor_out=xor(a,Encrpty_out)
                cipherblks.append(xor_out)
                iv=xor_out
            
        elif self.mode == 1:
            print("\n\t======Vernam Encryption PCBC=====\n")
            for a in msg_bitarray:
                pcbc_xor=xor(a,iv)
                pcbc_encrypt=VernamEncrypt(self.key_bitarray,pcbc_xor)
                cipherblks.append(pcbc_encrypt)
                iv=xor(a,pcbc_encrypt)
        
        elif self.mode==2:
            print("\n\t======Vernam Encryption CFB=====\n")
            for a in msg_bitarray:
                CFB_encrypt=VernamEncrypt(self.key_bitarray,iv)
                CFB_xor= xor(a,CFB_encrypt)
                iv=CFB_xor
                cipherblks.append(CFB_xor)
        
        return cipherblks

    def decrypt(self,cipherBlks):
        # Takes a list of cipher blocks and returns the
        # message. Again, decryption is based on mode.
        msg = ""
        msg_bits=[]
        iv=self.iv_bitarray
        if self.mode==0:
            print("\n\t======Vernam Decryption CBC=====\n")
            for a in cipherBlks:
                Decrypt_out=VernamDecrypt(self.key_bitarray,a)
                Xor_out=xor(Decrypt_out,iv)
                iv=a
                msg_bits.append(Xor_out)
        elif self.mode==1:
            print("\n\t======Vernam Decryption PCBC=====\n")
            for a in cipherBlks:
                pcbc_Decrypt=VernamDecrypt(self.key_bitarray,a)
                pcbc_xor= xor(pcbc_Decrypt,iv)
                msg_bits.append(pcbc_xor)
                iv=xor(a,pcbc_xor)
            
        elif self.mode==2:
            print("\n\t======Vernam Decryption CFB=====\n")
            for a in cipherBlks:
                CFB_encrypt=VernamEncrypt(self.key_bitarray,iv)
                CFB_xor= xor(a,CFB_encrypt)
                iv=a
                msg_bits.append(CFB_xor)
        
        # removing padding form the decryption
        if self.flag:
            sam=msg_bits[-1][-8:]                       # taking last byte of the msg list to check the padding bytes
            a=int(''.join([ "%d"%x for x in sam]),2)    #converting bin list array to integer
                        #print(sam,a)
            msg_bits[-1]=msg_bits[-1][:-(a*8)]          # removing the padding bits, a - padding in bytes (a*8) bits
        

        
        for i in msg_bits:
            msgs=bitarray_to_str(i)
            msg+=msgs
        return msg

if __name__ == '__main__':
    key = "secre_tr"
    iv = "whatever"
    msg = "This is my message.  There are many like it but this one is mine. "
    cipher=''
    d=des.DES()
    print("\nOriginal Plaintext: ",msg)
    blkChain = BlockChain(key,iv,VernamEncrypt,VernamDecrypt,BlockChain.CBC)
    cipherblks = blkChain.encrypt(msg)
    #print("Ciphertext:")
    for blk in cipherblks:
        cipher=cipher+bitarray_to_str(blk)
    print("Encrypted Ciphertext: ",cipher)
    #print("Decrypted:")
    msg = blkChain.decrypt(cipherblks)
    print("Decrypted Plaintext: ",msg)
