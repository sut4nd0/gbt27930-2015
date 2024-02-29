from decimal import Decimal
import argparse
import binascii
import csv
import json
import time

mul_frame_id = ["CEC56F4", "CECF456", "CEB56F4", "CECF456"]
addr = ["56", "F4"]
mul_frame_pgn = None
mul_frame_data = ""
mul_frame_num = None
mul_frame_byte = None
mul_frame_first = None


def format_data(data):
    data = data.split(" ")[-1]
    data = data.split("#")
    ci = data[0]
    cd = data[-1]
    return ci, cd


def get_pgn(ci):
    p = "00" + ci[2:4] + "00"
    p = int(p, 16)
    return str(p)


def orientation(ci):
    da = ci[4:6]
    sa = ci[6:]
    if sa in addr:
        if sa == addr[0]:
            sa = "充电机"
        else:
            sa = "BMS"
    else:
        sa = "???"
    if da in addr:
        if da == addr[0]:
            da = "充电机"
        else:
            da = "BMS"
    else:
        da = "???"

    return f"{sa}-{da}\t"


def pgn_message(p, pj):
    m = ""
    if p in pj:
        for k in pj[p]:
            m += f"{pj[p][k]}\t"
        return m


def pgn_content(p, cd):
    # print(p, cd)
    c = ""
    with open("SPN.json", "r", encoding="utf-8") as f:
        spn_json = json.load(f)
    for sl in spn_json[p]:
        if sl["process_mode"] == "select":
            if isinstance(sl["起始字节或位"], int):
                d = cd[(sl["起始字节或位"] - 1) * 2:(sl["起始字节或位"] + sl["长度"] - 1) * 2]
                if d:
                    d = (bytes.fromhex(d)[::-1].hex()).upper()
                    c += f'{sl["content"][sl["definition_data"].index(d)]}；'
            else:
                if sl["长度"] >= 8:
                    if sl["长度"] % 8 == 0:
                        n = int(sl["长度"] / 8 + sl["起始字节或位"])
                    else:
                        n = int(sl["长度"] / 8 + sl["起始字节或位"]) + 1
                else:
                    n = int(sl["起始字节或位"])
                d = cd[int(sl["起始字节或位"] - 1) * 2:n * 2]
                if d:
                    d = (bytes.fromhex(d)[::-1].hex()).upper()
                    db = bin(int(binascii.hexlify(bytes.fromhex(d)), 16))[2:].zfill(8 * (n - int(sl["起始字节或位"]) + 1))
                    sb = int(str(sl["起始字节或位"]).split('.')[1]) - 1
                    eb = sb + sl["长度"] + 1
                    if sb == 0:
                        eb = eb - 1
                    section = db[sb:eb]
                    try:
                        c += f'{sl["content"][sl["definition_data"].index(section)]}; '
                    except ValueError:
                        c += f'解析出错标准无{section}所代表的含义；'
        elif sl["process_mode"] == "ascii":
            if isinstance(sl["起始字节或位"], int):
                d = cd[(sl["起始字节或位"] - 1) * 2:(sl["起始字节或位"] + sl["长度"] - 1) * 2]
                if d:
                    ascii_string = ''.join(chr(int(d[i:i + 2], 16)) for i in range(0, len(d), 2))
                    c += f'{sl["content"]}{ascii_string}；'
        elif sl["process_mode"] == "calculate":
            if isinstance(sl["起始字节或位"], int):
                d = cd[(sl["起始字节或位"] - 1) * 2:(sl["起始字节或位"] + sl["长度"] - 1) * 2]
                if d:
                    d = (bytes.fromhex(d)[::-1].hex()).upper()
                    result = Decimal(str(sl["data_resolution"])) * Decimal(int(d, 16)) + sl["offset"]
                    if result < 0:
                        result = abs(result)
                    c += f'{sl["content"]}{result}{sl["units"]}；'
            else:
                if sl["长度"] >= 8:
                    if sl["长度"] % 8 == 0:
                        n = int(sl["长度"] / 8 + sl["起始字节或位"])
                    else:
                        n = int(sl["长度"] / 8 + sl["起始字节或位"])
                else:
                    n = int(sl["起始字节或位"])
                d = cd[int(sl["起始字节或位"] - 1) * 2:n * 2]
                if d:
                    db = bin(int(binascii.hexlify(bytes.fromhex(d)), 16))[2:].zfill(8 * (n - int(sl["起始字节或位"]) + 1))
                    sb = int(str(sl["起始字节或位"]).split('.')[1]) - 1
                    eb = sb + sl["长度"] + 1
                    if sb == 0:
                        eb = eb - 1
                    section = db[sb:eb]
                    result = Decimal(str(sl["data_resolution"])) * Decimal(int(section, 2)) + sl["offset"]
                    if result < 0:
                        result = abs(result)
                    c += f'{sl["content"]}{result}{sl["units"]}；'
        elif sl["process_mode"] == "date":
            if isinstance(sl["起始字节或位"], int):
                d = cd[(sl["起始字节或位"] - 1) * 2:(sl["起始字节或位"] + sl["长度"] - 1) * 2]
                if d:
                    if sl["SPN"] == "2571":
                        year = int(d[0:2], 16) + 1985
                        month = int(d[2:4], 16)
                        day = int(d[4:6], 16)
                        c += f'{sl["content"]}{year}年{month}月{day}日；'
                    elif sl["SPN"] == "2576":
                        year = int((bytes.fromhex(d[4:8])[::-1].hex()).upper(), 16)
                        month = int(d[2:4], 16)
                        day = int(d[0:2], 16)
                        c += f'{sl["content"]}{year}年{month}月{day}日；'
                    elif sl["SPN"] == "2823":
                        year = (bytes.fromhex(d[10:14])[::-1].hex()).upper()  # int(d[10:14], 16)
                        month = d[8:10]  # int(d[8:10], 16)
                        day = d[6:8]  # int(d[6:8], 16)
                        hour = d[4:6]  # int(d[4:6], 16)
                        minute = d[2:4]  # int(d[2:4], 16)
                        second = d[0:2]  # int(d[0:2], 16)
                        c += f'{sl["content"]}{year}年{month}月{day}日{hour}时{minute}分{second}秒；'
        elif sl["process_mode"] == "null":
            if isinstance(sl["起始字节或位"], int):
                d = cd[(sl["起始字节或位"] - 1) * 2:(sl["起始字节或位"] + sl["长度"] - 1) * 2]
                if d:
                    c += f'{sl["content"]}，帧数据为{d}；'
    return c


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="根据GB/T 27930-2015解析candump log或每行为\"can_id#can_data\"的文件")
    parser.add_argument("-f", "--file", help="指定要处理的文件路径")

    args = parser.parse_args()

    header = ["帧编号", "帧id", "阶段", "PGN", "报文代号", "报文描述", "优先权", "源地址-目的地址", "帧长度", "帧数据",
              "帧数据含义"]
    print("\t".join(header))

    t = time.strftime('%Y-%m-%d_%H%M%S', time.localtime())

    with open(f"analysis-{t}.csv", "w", newline="", encoding="utf-8") as output_file:
        writer = csv.writer(output_file, escapechar='\\', quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow(header)

        with open(args.file, "r", encoding="utf-8") as file1:
            with open("PGN.json", "r", encoding="utf-8") as pgn_file:
                pgn_json = json.load(pgn_file)
            line_num = 0

            for line in file1:
                content = ""
                line = line.strip()
                if line:
                    can_id, can_data = format_data(line)
                    data_len = f"{str(int(len(can_data) / 2))}\t"
                    pgn = get_pgn(can_id)
                    o = orientation(can_id)

                    if pgn in pgn_json:
                        message = f"{str(line_num)}\t0x{can_id}\t"
                        pm = pgn_message(pgn, pgn_json)
                        message += f"{pm}{o}{data_len}0x{can_data}\t"

                        content = pgn_content(pgn, can_data)
                        mc = message + content
                        print(mc)
                        writer.writerow(mc.split("\t"))
                    elif can_id[1:] in mul_frame_id:
                        pgn = str(int(can_data[10:], 16))
                        message = f"{str(line_num)}\t0x{can_id}\t"
                        pm = pgn_message(pgn, pgn_json)
                        message += f"{pm}{o}{data_len}0x{can_data}\t"

                        if can_data[0:2] == "10":
                            byte_num = str(int(can_data[2:4], 16))
                            frame_num = str(int(can_data[6:8], 16))
                            mul_frame_byte = byte_num
                            mul_frame_num = frame_num
                            content = f"多帧发送请求帧, 总字节数为{byte_num}, 需要发送的总帧数为{frame_num}"
                            mc = message + content

                            print(mc)
                            writer.writerow(mc.split("\t"))
                        elif can_data[0:2] == "11":
                            frame_num = str(int(can_data[2:4], 16))
                            first_frame = can_data[4:6]
                            mul_frame_first = 0
                            mul_frame_pgn = pgn
                            content = f"多帧请求响应帧, 可发送帧数为{frame_num}, 多帧发送时首帧的帧号为{first_frame}"
                            mc = message + content

                            print(mc)
                            writer.writerow(mc.split("\t"))
                        elif can_data[0:2] == "13":
                            receive_byte_num = int(can_data[2:4], 16)
                            receive_frame_num = int(can_data[6:8], 16)
                            content = f"多帧接收完成帧, 收到总字节数为{receive_byte_num}, 收到总帧数为{receive_frame_num}；\n多帧解析结果：【"

                            mul_frame_data = mul_frame_data[0:receive_byte_num * 2]

                            content += pgn_content(mul_frame_pgn, mul_frame_data) + "】"
                            mc = message + content

                            print(mc)
                            writer.writerow(mc.split("\t"))
                            mul_frame_pgn = None
                            mul_frame_data = ""
                            mul_frame_num = None
                            mul_frame_byte = None
                            mul_frame_first = None
                        elif can_data[0] == "0":
                            mul_frame_data += can_data[2:]
                            mul_frame_first += 1

                            message = f"{str(line_num)}\t0x{can_id}\t"
                            pm = pgn_message(mul_frame_pgn, pgn_json)
                            message += f"{pm}{o}{data_len}0x{can_data}\t"
                            content = f"多帧发送的第{mul_frame_first}帧"
                            mc = message + content

                            print(mc)
                            writer.writerow(mc.split("\t"))
                    else:
                        mc = f"{str(line_num)}\t0x{can_id}\t-\t-\t-\t-\t-\t{o}{data_len}0x{can_data}\t-"
                        print(mc)
                        writer.writerow(mc.split("\t"))
                line_num += 1
