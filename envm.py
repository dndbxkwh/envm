import argparse
import base64
import json
import os
import sys
import win32crypt
import winreg
from pathlib import Path
from datetime import datetime

########## Constants ##########
USER_META_DIR = Path(os.environ["LOCALAPPDATA"]) / "envm"
USER_META_FILE = USER_META_DIR / "envm.json"
USER_REG_PATH = "Environment"
SYS_REG_PATH = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
VALUE_MAX_LEN = 40

########## DPAPI ##########
def encrypt_value(plaintext: str) -> str:
    blob = win32crypt.CryptProtectData(plaintext.encode(), None, None, None, None, 0)
    return base64.b64encode(blob).decode()

def decrypt_value(enc_b64: str) -> str:
    blob = base64.b64decode(enc_b64)
    return win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1].decode()

########## Meta ##########
def load_meta(sys_flag=False):
    meta_file = USER_META_FILE if not sys_flag else USER_META_FILE.with_name("envm_sys.json")
    if not meta_file.exists():
        return {}
    return json.loads(meta_file.read_text(encoding="utf-8"))

def save_meta(data, sys_flag=False):
    meta_file = USER_META_FILE if not sys_flag else USER_META_FILE.with_name("envm_sys.json")
    USER_META_DIR.mkdir(parents=True, exist_ok=True)
    meta_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

########## Registry ##########
def open_reg(sys_flag=False, write=False):
    hive = winreg.HKEY_CURRENT_USER if not sys_flag else winreg.HKEY_LOCAL_MACHINE
    path = USER_REG_PATH if not sys_flag else SYS_REG_PATH
    access = winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE if write else winreg.KEY_QUERY_VALUE
    return winreg.OpenKey(hive, path, 0, access)

def reg_exists(key, sys_flag=False):
    try:
        winreg.QueryValueEx(open_reg(sys_flag), key)
        return True
    except FileNotFoundError:
        return False

def reg_set(key, value, sys_flag=False):
    with open_reg(sys_flag, True) as r:
        winreg.SetValueEx(r, key, 0, winreg.REG_SZ, value)

def reg_delete(key, sys_flag=False):
    with open_reg(sys_flag, True) as r:
        winreg.DeleteValue(r, key)

########## Utils ##########
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def parse_key_value(args):
    if len(args) == 1 and "=" in args[0]:
        return args[0].split("=", 1)
    if len(args) == 2:
        return args
    raise ValueError("KEY VALUE 또는 KEY=VALUE 형식만 허용됩니다")

def is_admin():
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def truncate_value(val):
    if len(val) > VALUE_MAX_LEN:
        return val[:VALUE_MAX_LEN - 3] + "..."
    return val

########## Commands ##########
def format_value(item, secret_show=False):
    try:
        val = decrypt_value(item.get("value_enc", "")) if "value_enc" in item else ""
    except:
        val = "<decrypt-error>"
    if item.get("secret") and not secret_show:
        val = "*" * item.get("len", 0)
    if not item.get("enabled", True):
        val = f"({val})"
    val = truncate_value(val)
    return val

def cmd_list(secret_show=False, sys_flag=False):
    data = load_meta(sys_flag)
    key_width = max([len("KEY")] + [len(k) for k in data]) + 2
    val_width = VALUE_MAX_LEN + 2
    ts_width = max([len("TIMESTAMP")] + [len(item.get("timestamp", "")) for item in data.values()]) + 2
    header = f"{'KEY'.ljust(key_width)} | {'VALUE'.ljust(val_width)} | {'TIMESTAMP'.ljust(ts_width)}"
    print(header)
    print("-" * len(header))
    for k in sorted(data):
        item = data[k]
        val_display = format_value(item, secret_show).ljust(val_width)
        timestamp = item.get("timestamp","").ljust(ts_width)
        print(f"{k.ljust(key_width)} | {val_display} | {timestamp}")

def cmd_show_key(key, sys_flag=False):
    data = load_meta(sys_flag)
    if key not in data:
        print(f"키 '{key}'가 envm 메타데이터에 없습니다.")
        return
    val_display = format_value(data[key], secret_show=is_admin())
    print(val_display)

def cmd_add(args, secret=False, sys_flag=False):
    key, value = parse_key_value(args)
    data = load_meta(sys_flag)
    if key in data:
        print(f"오류: 이미 envm이 관리 중인 키 '{key}'")
        return
    if not sys_flag and reg_exists(key):
        print(f"오류: 외부에서 생성된 환경변수 '{key}'는 추가할 수 없습니다")
        return
    reg_set(key, value, sys_flag)
    enc_value = encrypt_value(value)
    data[key] = {"value_enc": enc_value, "len": len(value), "timestamp": now(), "secret": secret, "enabled": True}
    save_meta(data, sys_flag)
    print(f"added {key}")

def cmd_modify(args, sys_flag=False):
    key, value = parse_key_value(args)
    data = load_meta(sys_flag)
    if key not in data:
        print(f"오류: envm이 관리하지 않는 키 '{key}'")
        return
    reg_set(key, value, sys_flag)
    enc_value = encrypt_value(value)
    data[key]["value_enc"] = enc_value
    data[key]["len"] = len(value)
    data[key]["timestamp"] = now()
    data[key]["enabled"] = True
    save_meta(data, sys_flag)
    print(f"modified {key}")

def cmd_remove(args, sys_flag=False):
    key = args[0]
    data = load_meta(sys_flag)
    if key not in data:
        print(f"오류: envm이 관리하지 않는 키 '{key}'")
        return
    if reg_exists(key, sys_flag):
        reg_delete(key, sys_flag)
    del data[key]
    save_meta(data, sys_flag)
    print(f"removed {key}")

def cmd_disable(args, sys_flag=False):
    key = args[0]
    data = load_meta(sys_flag)
    if key not in data:
        print(f"오류: envm이 관리하지 않는 키 '{key}'")
        return
    if reg_exists(key, sys_flag):
        reg_delete(key, sys_flag)
    data[key]["enabled"] = False
    save_meta(data, sys_flag)
    print(f"disabled {key}")

def cmd_enable(args, sys_flag=False):
    key = args[0]
    data = load_meta(sys_flag)
    if key not in data:
        print(f"오류: envm이 관리하지 않는 키 '{key}'")
        return
    if not reg_exists(key, sys_flag):
        try:
            val = decrypt_value(data[key]["value_enc"])
        except:
            val = ""
        reg_set(key, val, sys_flag)
    data[key]["enabled"] = True
    save_meta(data, sys_flag)
    print(f"enabled {key}")

########## Main ##########
def main():
    p = argparse.ArgumentParser(prog="envm", description="envm: 사용자/시스템 환경변수 관리 도구 (Windows 전용)")
    p.add_argument("-l", "--list", action="store_true", help="환경변수 목록 출력")
    p.add_argument("-ls", "--list-secret", action="store_true", help="환경변수 실제 value 출력 (관리자 필요)")
    p.add_argument("-a", "--add", nargs="+", help="환경변수 추가")
    p.add_argument("-as", "--add-secret", nargs="+", help="환경변수 추가(숨김)")
    p.add_argument("-m", "--modify", nargs="+", help="환경변수 수정")
    p.add_argument("-r", "--remove", nargs=1, help="환경변수 삭제")
    p.add_argument("-d", "--disable", nargs=1, help="환경변수 비활성화")
    p.add_argument("-e", "--enable", nargs=1, help="환경변수 활성화")
    p.add_argument("-s", "--sys", action="store_true", help="시스템 환경변수 대상")
    p.add_argument("key", nargs="?", help="특정 키 VALUE 출력")
    a = p.parse_args()
    sys_flag = a.sys
    if len(sys.argv) == 1:
        p.print_help()
    elif a.key:
        cmd_show_key(a.key, sys_flag)
    elif a.list:
        cmd_list(secret_show=False, sys_flag=sys_flag)
    elif a.list_secret:
        if not is_admin():
            print("관리자 권한 필요")
            return
        cmd_list(secret_show=True, sys_flag=sys_flag)
    elif a.add:
        cmd_add(a.add, secret=False, sys_flag=sys_flag)
    elif a.add_secret:
        cmd_add(a.add_secret, secret=True, sys_flag=sys_flag)
    elif a.modify:
        cmd_modify(a.modify, sys_flag=sys_flag)
    elif a.remove:
        cmd_remove(a.remove, sys_flag=sys_flag)
    elif a.disable:
        cmd_disable(a.disable, sys_flag=sys_flag)
    elif a.enable:
        cmd_enable(a.enable, sys_flag=sys_flag)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
