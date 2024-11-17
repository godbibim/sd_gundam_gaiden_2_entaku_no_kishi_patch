import sys
import struct
import os

import text_script
import subprocess

p8 = lambda x: struct.pack("<B", x)
p16 = lambda x: struct.pack("<H", x)
u16 = lambda x: struct.unpack("<H", x)[0]
ub16 = lambda x: struct.unpack(">H", x)[0]
pb16 = lambda x: struct.pack(">H", x)

path_origin = sys.argv[1]
path_output = "./temp/output.sfc"

data = open(path_origin, "rb").read()

# 데이터 패치 함수
def patch(data, offset, patch_data):
    """ 
    original_data = b"\x00\x01\x02\x03\x04"
    patch_data = b'\xFF\xFF'
    new_data = patch(original_data, 1, patch_data)
    print(new_data)  # 출력: b'\x00\xFF\xFF\x03\x04'
    """
    return data[:offset] + patch_data + data[offset + len(patch_data):]

# 확장된 롬의 사이즈 설정
NEW_ROM_HEADER_SIZE = 0x7FD7
data = patch(data, NEW_ROM_HEADER_SIZE,  b"\x0B")

# 2048KB 길이에 맞추기 위해 나머지 부분을 0x00으로 채웁니다.
data = data + b"\x00"*(0x200000-len(data))

# NEW_FONT_OFFSET: 새로운 폰트의 오프셋.
NEW_FONT_OFFSET = 0x106000

font = open("./data/hangul.fnt", "rb").read()
data = patch(data, NEW_FONT_OFFSET, font)


#코드 - 일본 폰트 위치의 이미지을 복사하여 확장된 뱅크 위치로 복붙
JA_FONT_FROM_ROM_OFFSET = 0xF8000
JA_FONT_TO_ROM_OFFSET = 0xFDBFF
JA_FONT_FROM_EXPAND_ROM_OFFSET = 0x100000
font_data = data[JA_FONT_FROM_ROM_OFFSET:JA_FONT_TO_ROM_OFFSET]
data = patch(data, JA_FONT_FROM_EXPAND_ROM_OFFSET, font_data)

#코드 - 한글 폰트 기계코드자리가 모잘라서 뱅크 스위치를 위한 코드
NEW_KO_BANK_SWITCH_OFFSET = 0x9088
NEW_KO_BANK_SWITCH_CODE_DATA = b'H\x8aJJJJJJJJ\xe2 \xc9\x0c\xb0!\xc9\x08\xb0\x16\xc9\x04\xb0\x0b\xc9\x00\xb0\x00\xc2 h\\\x00\x80$\xc2 h\\s\x80$\xc2 h\\\xe6\x80$\xc2 h\\Y\x81$\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea\xea'
data = patch(data, NEW_KO_BANK_SWITCH_OFFSET, NEW_KO_BANK_SWITCH_CODE_DATA)

# 1. 파일로 저장하기
with open('bacnk_code.bin', 'wb') as f:
    f.write(NEW_KO_BANK_SWITCH_CODE_DATA)

#코드 - 한글 폰트를 읽기 위한 코드
NEW_KO_READ_OFFSET = 0x120000
NEW_KO_READ_CODE_DATA = b'\x08\xc2 \xdaZ\x8a\xc9\xff\x07\xd0\x04d\x00\x80\x16)\x07\x00\n\n\n\n\x85\x00\x8a)\xf8\xff\n\n\n\n\n\x05\x00\x85\x00\xa9\x07\x00\x85\x04\xa6\x00\xa4\x02\xe2 \x8b\xa9~H\xab\xc2 \xbf\x00\x80 )\xff\x00\x99\x00\x80\xbf\x08\x80 )\xff\x00\x99\x10\x80\xbf\x80\x80 )\xff\x00\x99 \x80\xbf\x88\x80 )\xff\x00\x990\x80\xc8\xc8\xe8\xc6\x04\x10\xd1\xab\xa5\x02\x18i@\x00\x85\x02z\xfa(k\x08\xc2 \xdaZ\x8a\xc9\xff\x07\xd0\x04d\x00\x80\x16)\x07\x00\n\n\n\n\x85\x00\x8a)\xf8\xff\n\n\n\n\n\x05\x00\x85\x00\xa9\x07\x00\x85\x04\xa6\x00\xa4\x02\xe2 \x8b\xa9~H\xab\xc2 \xbf\x00\x00!)\xff\x00\x99\x00\x80\xbf\x08\x00!)\xff\x00\x99\x10\x80\xbf\x80\x00!)\xff\x00\x99 \x80\xbf\x88\x00!)\xff\x00\x990\x80\xc8\xc8\xe8\xc6\x04\x10\xd1\xab\xa5\x02\x18i@\x00\x85\x02z\xfa(k\x08\xc2 \xdaZ\x8a\xc9\xff\x07\xd0\x04d\x00\x80\x16)\x07\x00\n\n\n\n\x85\x00\x8a)\xf8\xff\n\n\n\n\n\x05\x00\x85\x00\xa9\x07\x00\x85\x04\xa6\x00\xa4\x02\xe2 \x8b\xa9~H\xab\xc2 \xbf\x00\x80")\xff\x00\x99\x00\x80\xbf\x08\x80")\xff\x00\x99\x10\x80\xbf\x80\x80")\xff\x00\x99 \x80\xbf\x88\x80")\xff\x00\x990\x80\xc8\xc8\xe8\xc6\x04\x10\xd1\xab\xa5\x02\x18i@\x00\x85\x02z\xfa(k\x08\xc2 \xdaZ\x8a\xc9\xff\x07\xd0\x04d\x00\x80\x16)\x07\x00\n\n\n\n\x85\x00\x8a)\xf8\xff\n\n\n\n\n\x05\x00\x85\x00\xa9\x07\x00\x85\x04\xa6\x00\xa4\x02\xe2 \x8b\xa9~H\xab\xc2 \xbf\x00\x00#)\xff\x00\x99\x00\x80\xbf\x08\x00#)\xff\x00\x99\x10\x80\xbf\x80\x00#)\xff\x00\x99 \x80\xbf\x88\x00#)\xff\x00\x990\x80\xc8\xc8\xe8\xc6\x04\x10\xd1\xab\xa5\x02\x18i@\x00\x85\x02z\xfa(k\xea\xea\xea\xea'
data = patch(data, NEW_KO_READ_OFFSET, NEW_KO_READ_CODE_DATA)

#마침표 수정
NEW_KO_PERIOD_OFFSET = 0x101CB0
NEW_KO_PERIOD_DATA = b"\x00\x00\x00\x00\x00\x70\x70\x70\x00\x00\x00\x00\x00\x00\x00\x00"
NEW_KO_PERIOD_DATA = bytes.fromhex('00 00 00 00 00 70 70 70 00 00 00 00 00 00 00 00')
data = patch(data, NEW_KO_PERIOD_OFFSET, NEW_KO_PERIOD_DATA)

#입력란 FF07값을 2E0C값으로 변경 = 입력란, 기타공백으로 사용되는데 한글을 사용하면서 원인을 알지 못하지만 지저분한 그림으로 채우는 문제를 추측으로 해결하고자 하는 코드
NEW_KO_INPUT_BATTLE_PLAYER_NAME_OFFSET = 0x2FD69
NEW_KO_INPUT_BATTLE_PLAYER_NAME_DATA = b"\x2E\x0C"
data = patch(data, NEW_KO_INPUT_BATTLE_PLAYER_NAME_OFFSET, NEW_KO_INPUT_BATTLE_PLAYER_NAME_DATA)


#Add version
NEW_VERSION_OFFSET = 0x10E560
VERSION_DATA = b"\x01" # 'Version1'
data = patch(data, NEW_VERSION_OFFSET, VERSION_DATA)
NEW_VERSION_OFFSET = 0xAF30F
data = patch(data, NEW_VERSION_OFFSET, VERSION_DATA)

#Add Credit User
NEW_CREDITS_POINTER_OFFSET = 0xAC7EB
NEW_CREDITS_POINTER_DATA = b"\x10\xF3"
NEW_CREDITS_OFFSET = 0xAF310
NEW_CREDITS_DATA_GODBIBIM_UPPER = b"\xF4\xFF\xB1\x00\xB9\x00\xAE\x00\xAC\x00\xB3\x00\xAC\x00\xB3\x00\xB7\x00\xFF\xFF" # 'GODBIBIM'
NEW_CREDITS_DATA_GODBIBIM_LOWER = b"\xF4\xFF\xCB\x00\xD3\x00\xC8\x00\xC6\x00\xCD\x00\xC6\x00\xCD\x00\xD1\x00\xFF\xFF" # 'godbibim'
 
data = patch(data, NEW_CREDITS_POINTER_OFFSET, NEW_CREDITS_POINTER_DATA)
data = patch(data, NEW_CREDITS_OFFSET, NEW_CREDITS_DATA_GODBIBIM_UPPER)

open("./temp/output_temp.bin", "wb").write(data)
data = text_script.run(data)
open("./temp/output.sfc", "wb").write(data)

# make patch file
if os.name == 'posix':
    with open(path_origin, 'rb') as f1, open(path_output, 'rb') as f2:
            origin_data = f1.read()
            output_data = f2.read()

    try:
        patch_file = "./temp/patch.xdelta"
        subprocess.run(["xdelta3", "-f", "-e", "-s", path_origin, path_output, patch_file]) #, creationflags=CREATE_NO_WINDOW)

    except Exception as e:
        print(f'오류 발생: {str(e)}')
        
