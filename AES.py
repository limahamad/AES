# Lima Hamad  143828
import random
import streamlit as st


s_box = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]

INV_S_BOX = [
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
]


r_con = [
    ['00', '00', '00', '00'],
    ['01', '00', '00', '00'],
    ['02', '00', '00', '00'],
    ['04', '00', '00', '00'],
    ['08', '00', '00', '00'],
    ['10', '00', '00', '00'],
    ['20', '00', '00', '00'],
    ['40', '00', '00', '00'],
    ['80', '00', '00', '00'],
    ['1b', '00', '00', '00'],
    ['36', '00', '00', '00']
]


C_matrix = [
    ['2', '3', '1', '1'],
    ['1', '2', '3', '1'],
    ['1', '1', '2', '3'],
    ['3', '1', '1', '2']
]


invC_matrix = [
    ['0e', '0b', '0d', '09'],
    ['09', '0e', '0b', '0d'],
    ['0d', '09', '0e', '0b'],
    ['0b', '0d', '09', '0e']
]


def subByte(plainText):
    for i in range(4):
        for j in range(4):
            if len(plainText[i][j]) == 1:
                row = 0
                col = int(plainText[i][j][0], 16)
            else:
                row = int(plainText[i][j][0], 16)
                col = int(plainText[i][j][1], 16)

            plainText[i][j] = format(s_box[row][col],'02x')

    return plainText


def subByteInv(plainText):
    for i in range(4):
        for j in range(4):
            if len(plainText[i][j]) == 1:
                row = 0
                col = int(plainText[i][j][0], 16)
            else:
                row = int(plainText[i][j][0], 16)
                col = int(plainText[i][j][1], 16)

    
            plainText[i][j] = format(INV_S_BOX[row][col],'02x')

    return plainText


def subByteCol(plainText):
    for j in range(4):
        if len(plainText[j]) == 1:
            row = 0
            col = int(plainText[j][0], 16)
        else:
            row = int(plainText[j][0], 16)
            col = int(plainText[j][1], 16)

        plainText[j] = format(s_box[row][col],'02x')

    return plainText


def ShiftRows(plaintText):
    for i in range(4):
        for q in range(i):
            temp = plaintText[i][0]
            for j in range(3):
                plaintText[i][j] = plaintText[i][j+1]
            plaintText[i][3] = temp

    return plaintText
        

def rowXcol(row, col):
    ans = 0
    for i in range(4):
        ans^= multiply(int(row[i], 16), int(col[i], 16))

    return hex(ans)[2:]


def multiply(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high_bit_set = a & 0x80
        a <<= 1
        if high_bit_set:
            a ^= 0x1b
        b >>= 1
    return p & 0xFF


def  mixColumn (plainText):
    ret = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            row = C_matrix[j]
            col = []
            for q in range(4):
                col.append(plainText[q][i])
            ret[j][i] = rowXcol(row, col)

    return ret 
        

def  mixColumnInv (plainText):
    ret = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            row = invC_matrix[j]
            col = []
            for q in range(4):
                col.append(plainText[q][i])
            ret[j][i] = rowXcol(row, col)

    return ret    


def XOR(a, b):
    ret = [0]*4
    for i in range(4):
        ret[i] = hex(int(a[i], 16) ^ int(b[i], 16))[2:]

    return ret


def keyExpantion(key):
    keyExpanded = [[]]*44
    for q in range(4):
        cur = []
        for i in range(4):
            cur.append(key[i][q])

        keyExpanded[q]= cur

    for i in range(4, 44):
        temp = []
        for f in keyExpanded[i-1]:
            temp.append(f)

        word =  keyExpanded[i-4]   #top of the current
  
        if i % 4 == 0:
            savedVAl = temp[0]
            for q in range(3):
                temp[q] = temp[q+1]
            temp[3] = savedVAl
            temp = subByteCol(temp)
            r_con_Send = r_con[int(i/4)]

            temp = XOR(temp, r_con_Send) 
 
        xord = XOR(word, temp)
        keyExpanded[i] = xord
  
    return keyExpanded


def AESEncryption(plainText, key, keys):
    # preRound
    plainText = addRountKey(plainText, keys[0:4])
    for i in range(10):
        plainText = subByte(plainText)

        plainText = ShiftRows(plainText)

        if i != 9:
            plainText = mixColumn(plainText)
        plainText = addRountKey(plainText, keys[(i+1)*4:(i+2)*4])

    return plainText


def ShiftRowsInv(plaintText):
    for i in range(4):
        for q in range(i):
            temp = plaintText[i][3]
            for j in reversed(range(1, 4)):
                plaintText[i][j] = plaintText[i][j-1]
            plaintText[i][0] = temp

    return plaintText


def AESDecryption(plainText, keys):
    plainText = addRountKey(plainText, keys[40:44])

    for i in range(10):
        plainText = ShiftRowsInv(plainText)
        plainText = subByteInv(plainText)
        plainText = addRountKey(plainText, keys[40-(i+1)*4:40-i*4])

        if i != 9:
            plainText = mixColumnInv(plainText)

    return plainText


def convertBin2Text(binary):
    str = ""
    for i in range(0, len(binary), 8):
        str+=chr(int(binary[i:i+8], 2))
  
    return str


def convertBin2hex(binary):
    strRet = ""
    for i in range(0, len(binary), 8):
        cur = str(hex(int(binary[i:i+8], 2))[2:])
        if len(cur) == 1:
            cur = "0"+cur
        strRet+=cur

    return strRet


def cusBin(num, wantedLen):
    str = ""
    for i in reversed(range(wantedLen)):
        if num & pow(2, i):
            str+="1"
        else:
            str+="0"

    return str


def convertText2Binary(text):
    binaryStr = ""
    l,m = [],[]
    for i in text:
        l.append(ord(i))

    for i in l:
        binary = cusBin(i, 8)
        m.append(binary)

    for k in m:
        binaryStr += str(k)

    return binaryStr


def genKey():
    key = ""
    for j in range(keySize):
        bit = random.randint(0, 1)
        key+=str(bit)
 
    return key


def convert2State(stream):
    state = [[0] * 4 for i in range(4)]
    cnt = 0
    for j in range(16):
        row = j % 4
        col = j // 4
        state[row][col] = hex(int(stream[cnt:cnt+2], 16))[2:]
        cnt+=2

    return state


def addRountKey(a, b):
    ret = [[0] * 4 for i in range(4)]
    for i in range(4):
        for j in range(4):
            temp = cusBin(int(a[i][j], 16) ^ int(b[j][i], 16), 8)
            ret[i][j] = convertBin2hex(temp)

    return ret


blockSize = 128
keySize = 128

def convertState2text(state):
    ret = ""
    for i in range(4):
        for j in range(4):
            if len(state[i][j]) == 1:
                ret+="0"
            ret +=state[j][i]

    return ret


def converHex2Text(hexText):
    str1 = ""
    for i in range(0, len(hexText), 2):
        str1+=chr(int(hexText[i:i+2], 16))
        
    return str1


def AES():
    # key = "5468617473206D79204B756E67204675"
    plainText = "smthing"
    selected_option = st.radio("Choose an option:", ("TEXT", "HEX"))
    f = 0
    h = ""
    if selected_option == "TEXT":
        h = st.text_input("Enter your Text")
        f = 1
    else:
        h = st.text_input("Enter hexadecimal representation of plaintext:(32 HEX digit)", key = 1)

    plainText = h
    if (f):
        binaryText = convertText2Binary(plainText)
        if len(binaryText)%blockSize:
            for i in range((blockSize - len(binaryText)%blockSize)):
                binaryText+='0'  #paddings

        binaryText = convertBin2hex(binaryText)
  
    else:
        binaryText = h


    selected_option2 = st.radio("Choose an option for the key:", ("Random generated", "Enter private key"))
    f2 = 0
    h2 = ""
    if selected_option2 == "Random generated":
        f2 = 1
    else:
        h2 = st.text_input("Enter private key:(32 HEX digit)", key = 2)

    if (f2):
        key = genKey()
        key = convertBin2hex(key)

    else:
        key = h2

    if (selected_option2 == "Random generated" or selected_option2 == "Enter private key" and h2 and h and selected_option):

        st.subheader("Plaintext in Hex Representation:")
        st.write(binaryText)
        # binaryText = "54776F204F6aeE65204E696E652054776F"
        st.subheader("Your key is:")
        st.write(key)
        key = convert2State(key)

        plain = ""
        cipher = ""
        keys = keyExpantion(key)

        for i in range(0, len(binaryText), blockSize):
            binaryText = convert2State(binaryText[i:i+blockSize])
            curCipher= AESEncryption(binaryText, key, keys)
            cipher+=convertState2text(curCipher)
            getBAck = AESDecryption(curCipher, keys)
            plain+= convertState2text(getBAck)


        st.subheader("Encrypted Text in hex:")
        st.write(cipher)

        st.subheader("Decrypted Text in hex:")
        st.write(plain)

        st.subheader("Decrypted Text (the original plaintext)")
        st.write(converHex2Text(plain))

        # print((binaryText))
        # print(curCipher)
        # print("Encryption results")
        # print(((cipher)))
        # print("Decryption results")
        # print(getBAck)
        # print((plain))
        # print(converHex2Text(plain))
    
    
if __name__ == "__main__":
    st.title("AES Encryption and Decryption")
    AES()
