import os
import csv
import struct
import json
from dataclasses import dataclass, field

#Defines the maximum number of items for dicts and sets.
os.environ['PYDEVD_CONTAINER_RANDOM_ACCESS_MAX_ITEMS'] = '4000'

p8 = lambda x: struct.pack("<B", x)
p16 = lambda x: struct.pack("<H", x)
u16 = lambda x: struct.unpack("<H", x)[0]
ub16 = lambda x: struct.unpack(">H", x)[0]
pb16 = lambda x: struct.pack(">H", x)

@dataclass
class StringTable:
    filename: str           = field(default="")
    pointer_start: int      = field(default=None)
    pointer_end: int        = field(default=None)
    base_address: int       = field(default=None)
    ko_pointer_start: int   = field(default=None)
    ko_pointer_end: int     = field(default=None)

def load_tbl(filename):
    tbl_dict = {}
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith(('@', '[')):
                if '=' in line:
                    hex_code, char = line.split('=', 1)
                    hex_code = hex_code.strip()
                    char = char.strip()
                    tbl_dict[bytes.fromhex(hex_code)] = char
    return tbl_dict

def read_uint16(data, offset):
    return u16(data[offset:offset+2])

def hex_to_int(data):
    return int(data, 16)

def check_end_condition(data, offset):
    # 종료 조건 리스트
    end_conditions = [
        b'\xFE\xFF',
        b'\xFF\xFF',
        # 여기에 추가 종료 조건들을 넣을 수 있습니다.
    ]
    
    for condition in end_conditions:
        if data[offset:offset+2] == condition:
            return True, condition
    
    return False, None

def find_best_match(memory_bytes, origin_memory_str, tbl_dict):
    best_match = None
    best_match_length = 0

    origin_bytes = bytes.fromhex(origin_memory_str)

    for key, value in tbl_dict.items():
        if key in memory_bytes and len(key) > best_match_length:
            best_match = value
            best_match_length = len(key)

    return best_match


def text_to_memory_hex(ko_text, ja_text, ja_memory_str, tbl_dict, best_match=False):
    memory_bytes = b''
    i = 0
    while i < len(ko_text):
        # Check for special tags enclosed in '[' and ']'
        if ko_text[i] == '[':
            end_index = ko_text.find(']', i)
            if end_index != -1:  # Valid tag found
                tag = ko_text[i:end_index + 1]  # Include ']' in the tag
                for hex_val, trans_char in tbl_dict.items():
                    if trans_char == tag:
                        memory_bytes += hex_val if isinstance(hex_val, bytes) else bytes(hex_val, 'ascii')
                        i = end_index + 1
                        break
                else:
                    print(f"[Warning] Unmatched1 tag: {tag} : {ko_text}")
                    i = end_index + 1
                continue
        elif ko_text[i] == '{' and ko_text[i:i+3] == '{ }':
            for hex_val, trans_char in tbl_dict.items():
                if trans_char == '{ }':
                    memory_bytes += hex_val if isinstance(hex_val, bytes) else bytes(hex_val, 'ascii')
                    i += 3  # Skip '{ }' pattern
                    break
            else:
                print("[Warning] Unmatched2 tag: '{ }'")
                i += 3
            continue
        elif ko_text[i] == '<':
            end_index = ko_text.find('>', i)
            if end_index != -1:  # Valid tag found
                tag = ko_text[i:end_index + 1]  # Include ']' in the tag
                for hex_val, trans_char in tbl_dict.items():
                    if trans_char == tag:
                        memory_bytes += hex_val if isinstance(hex_val, bytes) else bytes(hex_val, 'ascii')
                        i = end_index + 1
                        break
                else:
                    print(f"[Warning] Unmatched3 tag: {tag} : {ko_text}")
                    i = end_index + 1
                continue
        else:
            char = ko_text[i]
            if char == ' ':
                char = '{ }'
            
            for hex_val, trans_char in tbl_dict.items():
                if trans_char == char:
                    memory_bytes += hex_val if isinstance(hex_val, bytes) else bytes(hex_val, 'ascii')
                    break
            else:
                print(f"[Warning] Unmatched4 tag:\n"
                      f"    {ja_text}\n"
                      f"    {ko_text}\n"
                      f"    index {i} = {ko_text[i]}")
        
        i += 1

    
    # Convert final byte sequence to a formatted hex string
    return " ".join(f"{b:02X}" for b in memory_bytes)

def read_hex_to_string(data, offset, tbl_dict):
    result = ""
    start_offset = offset
    while True:
        # 최대 8바이트까지 검사 (4글자)
        for length in range(8, 0, -2):
            chunk = data[offset:offset+length]
            if chunk in tbl_dict:
                result += tbl_dict[chunk]
                offset += length
                break
        else:
            # 매칭되는 것이 없으면 2바이트를 unknown으로 처리
            unknown_value = ub16(data[offset:offset+2])
            result += f"[{unknown_value:04X}]"
            print(f"error={unknown_value:04X}")
            offset += 2

        is_end, end_condition = check_end_condition(data, offset)
        if is_end:
            if end_condition in tbl_dict:
                result += tbl_dict[end_condition]
            offset += 2
            break

    return result, offset, offset - start_offset

def write_file(filename, csv_data):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(csv_data)

# 데이터 패치 함수
def patch(data, offset, patch_data):
    """ 
    original_data = b"\x00\x01\x02\x03\x04"
    patch_data = b'\xFF\xFF'
    new_data = patch(original_data, 1, patch_data)
    print(new_data)  # 출력: b'\x00\xFF\xFF\x03\x04'
    """
    return data[:offset] + patch_data + data[offset + len(patch_data):]
        
def fill_with(data, start_offset, end_offset, fill_value=0xFF):
    """
    data에서 start_offset부터 end_offset까지 0xFF로 채운 새로운 데이터 반환
    """
    if start_offset > end_offset:
        raise ValueError("start_offset must be less than or equal to end_offset")
    
    fill_data = bytes([fill_value] * (end_offset - start_offset))
    return data[:start_offset] + fill_data + data[end_offset:]

def validate_csv(filename, header, end_markers=["[End]", "[Skip?]"]):
    with open(filename, 'r', encoding='utf-8') as csv_file:
        reader = csv.reader(csv_file)
        headers = next(reader)  # Skip the header row
        
        dialogue_idx = headers.index(header)

        for row in reader:
            dialogue = row[dialogue_idx]
            if len(dialogue) > 0:
                if not any(dialogue.endswith(marker) for marker in end_markers):
                    print(f"[Error] 오류: {header} 항목이 지정된 종료 문자열 중 하나로 끝나지 않음: {dialogue}")
            

    print(f"[Log] 검증 완료. {filename} ")

# Define column names as constants for better readability
COLUMN_NAMES = [
    "FIXED", "PRG", "주소(일어)", "포인터(일어)", "길이(일어)", "메모리(일어)", "대사(일어)", "대사(한국어)", "메모리(한국어)", "길이(한국어)", "포인터(한국어)", "길이차이", "주소(한국어)"
]

# Define column indices based on the constant column names
COL_FIXED = COLUMN_NAMES.index("FIXED") #체크하여 고정된 상태
COL_PRG = COLUMN_NAMES.index("PRG")
COL_JP_ADDRESS = COLUMN_NAMES.index("주소(일어)")
COL_JP_POINTER = COLUMN_NAMES.index("포인터(일어)")
COL_JP_LENGTH = COLUMN_NAMES.index("길이(일어)")
COL_JP_MEMORY = COLUMN_NAMES.index("메모리(일어)")
COL_JP_TEXT = COLUMN_NAMES.index("대사(일어)")
COL_KO_TEXT = COLUMN_NAMES.index("대사(한국어)")
COL_KO_MEMORY = COLUMN_NAMES.index("메모리(한국어)")
COL_KO_LENGTH = COLUMN_NAMES.index("길이(한국어)")
COL_KO_POINTER = COLUMN_NAMES.index("포인터(한국어)")
COL_LENGTH_DIFF = COLUMN_NAMES.index("길이차이")
COL_KO_ADDRESS = COLUMN_NAMES.index("주소(한국어)")

def extract_text(in_rom_bin, tbl_dict, params):

    pointer_start = params['pointer_start']
    pointer_end = params['pointer_end']
    base_address = params['base_address']
    filename = params['filename']

    csv_data = [COLUMN_NAMES]

    # 기존 CSV 파일에서 데이터 읽기(한글 번역 살리기)
    existing_data = {}
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)  # 헤더 건너뛰기
            for row in reader:
                #if len(row) >= len(COLUMN_NAMES):  # 모든 필요한 컬럼이 있는지 확인
                key = row[COL_PRG]  # PRG 주소를 키로 사용
                existing_data[key] = {
                    COLUMN_NAMES[COL_FIXED]: row[COL_FIXED],
                    COLUMN_NAMES[COL_KO_TEXT]: row[COL_KO_TEXT],
                    COLUMN_NAMES[COL_KO_MEMORY]: row[COL_KO_MEMORY]
                }

    for pointer_offset in range(pointer_start, pointer_end, 2):
        pointer = read_uint16(in_rom_bin, pointer_offset)
        address = base_address + pointer

        dialogue, end_offset, length = read_hex_to_string(in_rom_bin, address, tbl_dict)

        # Extract raw memory data for the current dialogue
        memory_data = in_rom_bin[address:end_offset]  # Slice data from address to end_offset (exclusive)
        memory_data_hex = " ".join(f"{b:02X}" for b in memory_data)  # Convert bytes to hex string with spaces

        # PRG 주소를 키로 사용
        prg_address = f"{pointer_offset:04X}"

        # 기존 데이터가 있으면 그것을 사용, 없으면 빈 문자열
        fixed = existing_data.get(prg_address, {}).get(COLUMN_NAMES[COL_FIXED], 'N')
        kor_trans = existing_data.get(prg_address, {}).get(COLUMN_NAMES[COL_KO_TEXT], '')
        kor_memory = existing_data.get(prg_address, {}).get(COLUMN_NAMES[COL_KO_MEMORY], '')

        csv_data.append([
            fixed,
            prg_address,
            f"{address:05X}",
            f"{pointer:04X}",
            length,
            memory_data_hex,
            dialogue,
            kor_trans,  # 기존 한국어 번역 유지
            kor_memory, # 기존 한국어 메모리 데이터 유지
            0,          # Placeholder for 길이(한국어)
            0,          # Placeholder for 포인터(한국어)
            0,          # Placeholder for 길이차이
            0,          # Placeholder for 주소(한국어)
        ])

    # Extend extract_text function to handle "대사(한국어)" to "메모리(한국어)" conversion
    for row in csv_data[1:]:  # Skip header row
        kor_text = row[COL_KO_TEXT]  # "대사(한국어)" column
        ja_text = row[COL_JP_TEXT]  # "대사(한국어)" column
        ja_memory = row[COL_JP_MEMORY]
        if kor_text:
            kor_memory_hex = text_to_memory_hex(kor_text, ja_text, ja_memory, tbl_dict, True)
            row[COL_KO_MEMORY] = kor_memory_hex  # Update "메모리(한국어)" column with converted hex

            # Calculate and update "길이(한국어)" and "길이차이"
            kor_length = len(kor_memory_hex.split(" "))  # Calculate byte length of "메모리(한국어)"
            row[COL_KO_LENGTH] = kor_length  # "길이(한국어)"
            row[COL_LENGTH_DIFF] = row[COL_JP_LENGTH] - kor_length  # "길이차이" (difference between "길이(일어)" and "길이(한국어)")       

    write_file(filename, csv_data)
    validate_csv(filename, COLUMN_NAMES[COL_JP_TEXT])
    validate_csv(filename, COLUMN_NAMES[COL_KO_TEXT])
            
    print(f"[Log] 추출 완료. extract_text - CSV 파일이 {filename}에 저장되었습니다.")
    
    return csv_data

def write_ko_pointer_data(tbl_dict, params, csv_data):
    pointer_start = params['pointer_start']
    pointer_end = params['pointer_end']
    base_address = params['base_address']
    filename = params['filename']

    start_pointer = hex_to_int(csv_data[1][COL_JP_POINTER])
    ko_accumulated_length = 0
    ja_accumulated_length = 0
    in_bounds_pointer = set()

    pre_ja_pointer = 0
    for row in csv_data[1:]:
        kor_text = row[COL_KO_TEXT]
        ja_pointer = row[COL_JP_POINTER]
        if pre_ja_pointer != ja_pointer:
            if 1 in in_bounds_pointer:
                print("'{1}'이 이전에 존재한 포인터(비연속적임에 데이터 삽입 주의 필요)")

            if kor_text:
                new_bytes = (start_pointer + ko_accumulated_length).to_bytes(length=2, byteorder='big').hex().upper()  # 4바이트로 변환
                row[COL_KO_POINTER] = new_bytes

                ko_pointer = base_address + hex_to_int(row[COL_KO_POINTER])
                ko_pointer_hex = hex(ko_pointer).upper()[2:]
                row[COL_KO_ADDRESS] = ko_pointer_hex
                ko_accumulated_length += row[COL_KO_LENGTH]
                ja_accumulated_length += row[COL_JP_LENGTH]
                pre_ja_pointer = ja_pointer
                in_bounds_pointer.add(pre_ja_pointer)
                
                params['ko_pointer_end'] = hex(ko_pointer + row[COL_KO_LENGTH]).upper()[2:]
        else:
            row[COL_KO_POINTER] = new_bytes
            row[COL_KO_ADDRESS] = ko_pointer_hex

    if ko_accumulated_length > ja_accumulated_length:
        print(f"[Error] memory size ko({ko_accumulated_length})-ja({ja_accumulated_length}) = {ko_accumulated_length - ja_accumulated_length}")
    else:
        print(f"[Log] memory size ko({ko_accumulated_length})-ja({ja_accumulated_length}) = {ko_accumulated_length - ja_accumulated_length}")

    for row in csv_data[-1:]:
        # 일본어와 한국어 텍스트의 끝 지점 계산
        JP_END_ADDRESS = hex_to_int(row[COL_JP_ADDRESS]) + row[COL_JP_LENGTH]
        KO_END_ADDRESS = hex_to_int(row[COL_KO_ADDRESS]) + row[COL_KO_LENGTH]
        params['JP_END_ADDRESS'] = JP_END_ADDRESS
        params['KO_END_ADDRESS'] = KO_END_ADDRESS
        print(f"\t* JP_END_ADDRESS {hex(JP_END_ADDRESS)}")
        print(f"\t* KO_END_ADDRESS {hex(KO_END_ADDRESS)}")

    # Write updated data back to CSV
    write_file(filename, csv_data)

    print(f"\t* ko_pointer_end = {params['ko_pointer_end']}")
    print(f"\t* 추출 완료. write_ko_pointer_data - CSV 파일이 {filename}에 저장되었습니다.")


def insert_korean_text(in_rom_bin, tbl_dict, params):
    pointer_start = params['pointer_start']
    pointer_end = params['pointer_end']
    base_address = params['base_address']
    filename = params['filename']
    
    korean_data = {}
    with open(filename, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)  # 헤더 건너뛰기
        
        for row in reader:
            prg_address = row[COL_PRG]
            ko_memory = row[COL_KO_MEMORY]
            ko_length = int(row[COL_KO_LENGTH]) if row[COL_KO_LENGTH] else 0
            
            if ko_memory and ko_memory.strip():  # 한국어 메모리 데이터가 있는 경우만
                korean_data[prg_address] = {
                    'memory_data': ko_memory,
                    'length': ko_length,
                    'ko_pointer': row[COL_KO_POINTER],
                    'ko_address': row[COL_KO_ADDRESS]
                }
            # else:
            #     raise Exception("항목이 비어있다")
    
    # `modified_rom` 초기값을 `in_rom_bin`로 설정
    modified_rom = in_rom_bin

    for pointer_offset in range(pointer_start, pointer_end, 2):
        prg_address = f"{pointer_offset:04X}"
        
        if prg_address in korean_data:
            NEW_POINTER_OFFSET = hex_to_int(prg_address)

            ko_pointer_offset = korean_data[prg_address]['ko_pointer']
            pointer_value = hex_to_int(ko_pointer_offset)
            NEW_POINTER_DATA = pointer_value.to_bytes(len(ko_pointer_offset) // 2, byteorder='little')
            
            modified_rom = patch(modified_rom, NEW_POINTER_OFFSET, NEW_POINTER_DATA)
            
            ko_trans_address = korean_data[prg_address]['ko_address']
            NEW_TRANS_OFFSET = hex_to_int(ko_trans_address)

            temp = korean_data[prg_address]['memory_data']
            NEW_TRANS_DATA = bytes.fromhex(temp)

            modified_rom = patch(modified_rom, NEW_TRANS_OFFSET, NEW_TRANS_DATA)

    return modified_rom

############################################################################################################

def run(rom_data):
    
    tbl_dict = load_tbl("./data/script.korea.tbl")

    with open('./data/config.json', 'r') as f:
        configs = json.load(f)
    
    for key in configs:
        print("")
        print("--Start----------------------------")
        print("")

        script_param = configs[key]

        script_param['pointer_start'] = int(script_param['pointer_start'], 16)
        script_param['pointer_end'] = int(script_param['pointer_end'], 16)
        script_param['base_address'] = int(script_param['base_address'], 16)
        patch_ko = script_param['patch_ko']

        csv_data = extract_text(rom_data, tbl_dict, script_param)

        if patch_ko:
            write_ko_pointer_data(tbl_dict, script_param, csv_data)

        # 일본어 끝 지점이 한국어 끝 지점보다 크다면
        # JP_END_ADDRESS에서 KO_END_ADDRESS까지의 범위를 0xFF로 채움
        JP_END_ADDRESS = script_param['JP_END_ADDRESS']
        KO_END_ADDRESS = script_param['KO_END_ADDRESS']

        if script_param['fill_empty']:
            rom_data = fill_with(rom_data, KO_END_ADDRESS, JP_END_ADDRESS, 0xFF)
        
        rom_data = insert_korean_text(rom_data, tbl_dict, script_param)
        
        #필요에 따라 이어서 데이터를 붙일 곳 위치를 지정
        # Lexicon1_2params['ko_pointer_start'] = Lexicon1_1params['ko_pointer_end']

    return rom_data

if __name__ == "__main__":
    rom_data = open("./temp/output_temp.bin", "rb").read()
    rom_data = run(rom_data)
    open("./temp/output.sfc", "wb").write(rom_data)
