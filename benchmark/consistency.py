import re
import os

def extract_committed_digests(log_file):
    """
    提取 log 文件中所有形如 'commit Block node X batch_id Y' 的字符串，
    并返回其按顺序组成的 (node_id, batch_id) 列表。
    """
    pattern = re.compile(r'commit Block node (\d+) batch_id (\d+)')
    digests = []
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            digests.extend(pattern.findall(line))
    return digests

def remove_duplicates(seq):
    """
    保留顺序地移除重复项，返回去重后的列表和重复项数量。
    """
    seen = set()
    result = []
    duplicate_count = 0
    for item in seq:
        if item not in seen:
            seen.add(item)
            result.append(item)
        else:
            duplicate_count += 1
    return result, duplicate_count

def compare_digest_sequences(log_files):
    """
    比较多个 log 文件中 committed digest 序列是否为最长序列的前缀（基于去重后的序列），
    并检查每个文件中重复条目的数量。
    """
    digest_sequences = {}
    duplicate_counts = {}
    all_match = True

    print("🔍 正在提取并处理 committed 序列...\n")

    for log_file in log_files:
        digests = extract_committed_digests(log_file)
        unique_digests, duplicate_count = remove_duplicates(digests)
        digest_sequences[log_file] = unique_digests
        duplicate_counts[log_file] = duplicate_count

        if duplicate_count > 0:
            print(f"⚠️ 文件 {log_file} 中有 {duplicate_count} 个重复 commit。")
        else:
            print(f"✅ 文件 {log_file} 中无重复 commit。")

    print("\n🔍 正在比较去重后的 committed 序列是否一致...\n")

    # 找出最长的去重序列作为参考
    ref_file, ref_digests = max(digest_sequences.items(), key=lambda item: len(item[1]))

    for file, digests in digest_sequences.items():
        if file == ref_file:
            print(f"🔹 文件 {file} 是最长的参考序列。")
            continue

        expected = ref_digests[:len(digests)]
        if digests != expected:
            print(f"❌ 文件 {file} 的 committed 序列与 {ref_file} 不一致（基于去重后的序列）。")
            for i, (d1, d2) in enumerate(zip(digests, expected)):
                if d1 != d2:
                    print(f"  ↪️ 第 {i} 项不同: {file} 为 {d1}，参考为 {d2}")
                    break
            all_match = False
        else:
            print(f"✅ 文件 {file} 的 committed 序列是 {ref_file} 的前缀（基于去重后的序列）。")

    return all_match

if __name__ == '__main__':
    log_dir = 'logs/2025-05-22v22-18-31'
    log_files = [
        os.path.join(log_dir, 'node-info-0.log'),
        os.path.join(log_dir, 'node-info-1.log'),
        os.path.join(log_dir, 'node-info-2.log'),
        os.path.join(log_dir, 'node-info-3.log'),
    ]
    compare_digest_sequences(log_files)
