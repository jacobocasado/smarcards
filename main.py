# This is a sample Python script.

# Press Mayús+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


from Crypto.Cipher import DES3, DES
import pyDes


def des3_encrypt(plaintext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(plaintext)


def des_encrypt(plaintext, key, iv):
    cipher = DES.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(plaintext)


def generate_session_key(nt, ak, terminal_rn):

    nt = '0021'

    ak_hex = "101112131415161718191A1B1C1D1E1F"
    print("La Administrative Key en hexadecimal vale: ", ak_hex)

    half_length = len(ak_hex) // 2
    ak1 = ak_hex[:half_length]
    ak2 = ak_hex[half_length:]

    ak12 = ak_hex
    ak21 = ak2 + ak1
    print("AK1|2 vale: ", ak12)
    print("AK2|1 vale: ", ak21)

    padded_nt = ['00', '00', '00', nt, '00', '00', '00']
    padded_nt = bytes.fromhex(' '.join(padded_nt))

    print("NT paddeado: ", padded_nt.hex())

    tsk1 = des3_encrypt(padded_nt, bytes.fromhex(ak12), int.to_bytes(0, 8, 'big'))
    tsk1 = tsk1.hex()
    print("TSK1: ", tsk1)

    tsk2 = des3_encrypt(padded_nt, bytes.fromhex(ak21), int.to_bytes(0, 8, 'big'))
    tsk2 = tsk2.hex()

    print("TSK2: ", tsk2)

    # Convierte a int
    int1 = int(tsk1, 16)
    int2 = int(tsk2, 16)

    # Une los valores utilizando el operador de desplazamiento de bits
    result = (int1 << 64) + int2

    # Convierte el resultado a hexadecimal y formatea la salida para eliminar el prefijo '0x'
    hex_result = format(result, 'x')

    # Convierte a bytes
    result_bytes = bytes.fromhex(hex_result)

    print("TSK: ", hex_result)

    terminal_rn = bytes.fromhex(' '.join(terminal_rn))
    print("CRN generandose haciendo un 3DES con {} como clave y {} como plaintext:".format(result_bytes, terminal_rn))
    crn = des3_encrypt(terminal_rn, result_bytes, int.to_bytes(0, 8, 'big'))
    crn = crn.hex()
    print("CRN:", crn)

    nt = '0022'

    padded_nt = ['00', '00', '00', nt, '00', '00', '00']
    padded_nt = bytes.fromhex(' '.join(padded_nt))
    print("NT paddeado (SEGUNDA VUELTA): ", padded_nt.hex())

    sk1 = des3_encrypt(padded_nt, bytes.fromhex(ak12), int.to_bytes(0, 8, 'big'))
    sk1 = sk1.hex()
    print("SK1: ", sk1)

    sk2 = des3_encrypt(padded_nt, bytes.fromhex(ak21), int.to_bytes(0, 8, 'big'))
    sk2 = sk2.hex()

    print("SK2: ", sk2)

    # Convierte a int
    int1 = int(sk1, 16)
    int2 = int(sk2, 16)

    # Une los valores utilizando el operador de desplazamiento de bits
    result = (int1 << 64) + int2

    # Convierte el resultado a hexadecimal y formatea la salida para eliminar el prefijo '0x'
    hex_result = format(result, 'x')

    print("SK:", hex_result)

    return hex_result, sk1, sk2


def encrypt_list_of_bytes(lst, key, sk1):
    encrypted_lst = []
    prev = b"\0\0\0\0\0\0\0\0"

    key = bytes.fromhex(key)
    sk1 = bytes.fromhex(sk1)

    for i, b in enumerate(lst):
        b = bytes.fromhex(b)
        if i == 0:
            print("Encriptando bloque INICIAL que vale {} con la SK1 que vale {}".format(b,sk1))
            encrypted_block = des_encrypt(b, sk1, int.to_bytes(0, 8, 'big'))
            print("Resultado de la encriptación del primer bloque: ", encrypted_block.hex())
            prev = encrypted_block

        elif i == len(lst) - 1:
            print("Encriptando bloque FINAL. \n\t El bloque vale {} y se va a hacer un XOR con el bloque {}.".format(b,
                                                                                                                     prev))
            xored = bytes([a ^ b for a, b in zip(prev, b)])
            print("\tResultado de la operación XOR:", xored.hex())
            encrypted_block = des3_encrypt(xored, key, int.to_bytes(0, 8, 'big'))
            print("Resultado de la encriptación del bloque último que vale {} con la clave que vale {}: ".format(
                xored.hex(), key.hex()), encrypted_block.hex())

        else:
            xored = bytes([a ^ b for a, b in zip(prev, b)])
            print("\tResultado de la operación XOR:", xored.hex())
            encrypted_block = des_encrypt(xored, sk1, int.to_bytes(0, 8, 'big'))
            print("Resultado de la encriptación del bloque intermedio {} con la clave SK1 que vale ". format(b, sk1), encrypted_block.hex())
            prev = encrypted_block

        encrypted_lst.append(encrypted_block)

    cont = 0
    for element in encrypted_lst:
        hex_values = [hex(b) for b in element]
        print("Bloque {} =".format(cont), hex_values)
        cont = cont + 1

    return encrypted_lst


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    ak = "UC3M-MASTERKEY01"
    nt = 0
    rn = ['01', '02', '03', '04', '05', '06', '07', '08']

    sk, sk1, sk2 = generate_session_key(nt, ak, rn)

    command = "040600000D"
    print(command)
    data = '77146828BK'
    data = data.encode('ascii').hex()
    data = str(data)

    all = command + data
    print(all)

    block_size = 16
    blocks = [all[i:i + block_size] for i in range(0, len(all), block_size)]

    if len(blocks[-1]) < block_size:
        blocks[-1] = blocks[-1].ljust(block_size, '0')

    print(blocks)

    encrypt_list_of_bytes(blocks, sk, sk1)
