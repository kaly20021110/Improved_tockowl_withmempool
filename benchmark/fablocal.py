import subprocess
import time

for i in range(20):
    print(f"\n[执行第 {i + 1} 次] fab local")
    try:
        result = subprocess.run(["fab", "local"], capture_output=True, text=True, check=True)
        print("✅ 执行成功")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("❌ 执行失败")
        print("错误输出：", e.stderr)
        break  # 失败就中断

    if i < 19:  # 最后一轮就不再 sleep 了
        print("⏳ 等待 3 秒再继续下一轮...\n")
        time.sleep(3)
