import requests
import argparse
import threading

def banner():
    banner_text = """ 
                          _   _                _             _ 
                         | | | |              (_)           | |
  _   _ _ __   __ _ _   _| |_| |__   ___  _ __ _ _______  __| |
 | | | | '_ \ / _` | | | | __| '_ \ / _ \| '__| |_  / _ \/ _` |
 | |_| | | | | (_| | |_| | |_| | | | (_) | |  | |/ /  __/ (_| |
  \__,_|_| |_|\__,_|\__,_|\__|_| |_|\___/|_|  |_/___\___|\__,_|   """
    print(banner_text)

# 定义锁，用于控制输出
print_lock = threading.Lock()
parser = argparse.ArgumentParser(description='未授权访问漏洞检测')
parser.add_argument('-u', type=str, help='url:port', required=False)  # 单个URL参数
parser.add_argument('-f', type=str, help='文件名，包含要检测的URL列表', required=False)  # 批量检测的文件参数
args = parser.parse_args()

def checkVuln(url):
    """ 检查单个URL的漏洞 """
    try:
        attack_url = url.strip() + "/info"
        response = requests.get(attack_url, timeout=5)  # 设置请求超时
        with print_lock:
            if response.status_code == 200:
                print(f"[+] 目标网址 {url} 存在漏洞未授权访问漏洞")
            else:
                print(f"[-] 目标网址 {url} 不存在漏洞")
    except requests.RequestException as e:
        with print_lock:
            print(f"[*] 与目标连接失败！错误信息: {e}")

def checkFile(filename):
    """ 批量检查文件中列出的所有URL """
    try:
        with open(filename, "r") as f:
            threads = []
            for readline in f.readlines():
                url = readline.strip()  # 移除换行符
                if url:  # 确保url不为空
                    # 创建线程并启动
                    thread = threading.Thread(target=checkVuln, args=(url,))
                    thread.start()
                    threads.append(thread)

            # 等待所有线程完成
            for thread in threads:
                thread.join()

    except FileNotFoundError:
        print(f"[*] 文件 {filename} 未找到，请检查路径。")
    except Exception as e:
        print(f"[*] 读取文件时出错: {e}")

if __name__ == "__main__":
    banner()
    if args.u:
        # 如果提供单个URL，创建一个线程来处理
        thread = threading.Thread(target=checkVuln, args=(args.u,))
        thread.start()
        thread.join()  # 等待线程完成
    elif args.f:
        checkFile(args.f)
    else:
        print("请提供一个URL（使用 -u）或一个包含URL的文件（使用 -f）。")
