import re
import os

def extract_committed_digests(log_file):
    """
    提取给定 log 文件中所有形如 'Committed [digest]' 的字符串，并按顺序返回 digest 列表。
    """
    pattern = re.compile(r'commit Block node (\d+) batch_id (\d+)')
    digests = []
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            digests.extend(pattern.findall(line))
    return digests

def compare_digest_sequences(log_files):
    """
    比较多个 log 文件中的 committed digest 序列是否为最长序列的前缀。
    """
    digest_sequences = {}
    for log_file in log_files:
        digests = extract_committed_digests(log_file)
        digest_sequences[log_file] = digests

    # 找出最长的 committed digest 序列作为参考
    ref_file, ref_digests = max(digest_sequences.items(), key=lambda item: len(item[1]))

    # 逐个比较每个文件的序列是否是最长序列的前缀
    all_match = True
    for file, digests in digest_sequences.items():
        expected = ref_digests[:len(digests)]
        if digests != expected:
            print(f"文件 {file} 的 committed digest 序列不是 {ref_file} 的前缀。")
            all_match = False
        else:
            print(f"文件 {file} 的 committed digest 序列是 {ref_file} 的前缀。")

    return all_match



if __name__ == '__main__':
    # 指定 logs 目录下的文件
    log_dir = 'logs/2025-05-19v09-51-03'
    log_files = [
        os.path.join(log_dir, 'node-info-0.log'),
        os.path.join(log_dir, 'node-info-1.log'),
        os.path.join(log_dir, 'node-info-2.log'),
        os.path.join(log_dir, 'node-info-3.log'),
    ]
    compare_digest_sequences(log_files)