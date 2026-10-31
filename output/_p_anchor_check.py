# SPDX-License-Identifier: CC-BY-SA-4.0
# 一次性量具：日锚（day_manifest.json）逐日核对。只读，零写入。
#   锚 = {size, last_hash, updated_at}
#   验三件事：①有没有锚 ②size 是否等于实际 ③last_hash 是否等于末条记录 hash
import hashlib
import json
import os
import sys

ROOT = ".psl/audit"
MANIFEST = os.path.join(ROOT, "day_manifest.json")


def day_files(root):
    return [os.path.join(root, n) for n in sorted(os.listdir(root))
            if n.endswith(".jsonl") and len(n) == 16 and n[4] == "-"]


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    man = {}
    if os.path.exists(MANIFEST):
        with open(MANIFEST, "r", encoding="utf-8") as f:
            man = json.load(f)

    files = day_files(ROOT)
    names = {os.path.basename(p) for p in files}

    print("日文件 %d 个｜锚条目 %d 条" % (len(files), len(man)))
    print("有文件无锚：%s" % (sorted(names - set(man)) or "无"))
    print("有锚无文件：%s" % (sorted(set(man) - names) or "无"))
    print()

    hdr = "%-20s %10s %10s %6s  %-8s %s"
    print(hdr % ("day", "actual", "anchor", "size", "hash", "updated_at"))
    bad_size = []
    bad_hash = []
    no_hash = 0
    for p in files:
        n = os.path.basename(p)
        sz = os.path.getsize(p)
        e = man.get(n)
        if not e:
            print("%-20s %10d %10s %6s  %-8s %s" % (n[:10], sz, "-", "无锚", "-", "-"))
            continue
        asz = e.get("size")
        ah = e.get("last_hash")
        # 末条记录的 hash：取最后一行非空
        last_hash = None
        with open(p, "rb") as f:
            data = f.read()
        lines = [x for x in data.split(b"\n") if x.strip()]
        if lines:
            try:
                rec = json.loads(lines[-1].decode("utf-8", "replace"))
                if isinstance(rec, dict):
                    last_hash = rec.get("hash")
            except Exception:
                pass
        if last_hash is None:
            no_hash += 1
        ok_sz = (asz == sz)
        ok_h = (ah == last_hash)
        if not ok_sz:
            bad_size.append((n[:10], asz, sz))
        if ah and last_hash and not ok_h:
            bad_hash.append((n[:10], ah[:12], last_hash[:12]))
        print("%-20s %10d %10s %6s  %-8s %s" % (
            n[:10], sz, asz, "OK" if ok_sz else "差",
            "OK" if ok_h else ("n/a" if last_hash is None else "差"),
            e.get("updated_at")))

    print()
    print("size 不符 %d 天：%s" % (len(bad_size), bad_size or "无"))
    print("last_hash 不符 %d 天：%s" % (len(bad_hash), bad_hash or "无"))
    print("末条无 hash 的天数：%d" % no_hash)


if __name__ == "__main__":
    main()
