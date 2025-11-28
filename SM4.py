import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from gmssl import sm4
import os
import binascii

# --- SM4 核心逻辑 ---

class SM4Processor:
    BLOCK_SIZE = 16  # SM4 分组大小为 16 字节

    @staticmethod
    def process_sm4(data_hex, key_hex, iv_hex, mode, action):
        """
        处理 SM4 加密/解密的核心函数 (无填充模式).
        数据、密钥和 IV 均以十六进制字符串形式传入。
        """
        try:
            # 1. 转换为字节 (Bytes)
            data_bytes = binascii.unhexlify(data_hex.strip())
            key_bytes = binascii.unhexlify(key_hex.strip())
            
            if mode == 'CBC':
                iv_bytes = binascii.unhexlify(iv_hex.strip())
            else:
                iv_bytes = None

            # 2. 长度校验
            if len(key_bytes) != SM4Processor.BLOCK_SIZE:
                return False, "密钥长度必须为 16 字节 (32 位十六进制字符)。"
            
            if mode == 'CBC' and len(iv_bytes) != SM4Processor.BLOCK_SIZE:
                 return False, "CBC 模式下 IV 长度必须为 16 字节 (32 位十六进制字符)。"

            # 3. NoPad 模式下的数据长度校验
            if len(data_bytes) % SM4Processor.BLOCK_SIZE != 0:
                return False, f"NoPad 模式要求数据长度必须是 {SM4Processor.BLOCK_SIZE} 字节的整数倍。"

            # 4. 初始化 SM4 对象
            sm4_obj = sm4.CryptSM4(key_bytes, mode=mode)
            
            # 5. 执行操作
            if action == 'encrypt':
                if iv_bytes:
                    sm4_obj.set_iv(iv_bytes)
                result_bytes = sm4_obj.encrypt(data_bytes)
            else: # action == 'decrypt'
                if iv_bytes:
                    sm4_obj.set_iv(iv_bytes)
                result_bytes = sm4_obj.decrypt(data_bytes)

            # 6. 返回结果
            result_hex = binascii.hexlify(result_bytes).decode('utf-8')
            return True, result_hex
            
        except binascii.Error:
            return False, "输入包含非十六进制字符，请检查数据、密钥和 IV。"
        except Exception as e:
            return False, f"处理失败：{e}"


# --- GUI 界面设置 ---

class SM4App:
    def __init__(self, master):
        self.master = master
        master.title("SM4 (ECB/CBC NoPad) 加密解密工具")
        
        # 默认值
        self.key_default = binascii.hexlify(os.urandom(16)).decode('utf-8') # 随机生成一个默认 key (16字节)
        self.iv_default = binascii.hexlify(os.urandom(16)).decode('utf-8') # 随机生成一个默认 IV (16字节)
        self.mode_var = tk.StringVar(value='ECB')

        # 构建界面
        self._create_widgets()

    def _create_widgets(self):
        # 1. 容器 Frame
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 2. 密钥和 IV 输入
        ttk.Label(main_frame, text="密钥 (32位 Hex):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(main_frame, width=50)
        self.key_entry.insert(0, self.key_default)
        self.key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(main_frame, text="IV (32位 Hex, CBC必填):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.iv_entry = ttk.Entry(main_frame, width=50)
        self.iv_entry.insert(0, self.iv_default)
        self.iv_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))

        # 3. 模式选择 (Radio Buttons)
        ttk.Label(main_frame, text="模式 (NoPad):").grid(row=2, column=0, sticky=tk.W, pady=5)
        
        mode_frame = ttk.Frame(main_frame)
        ttk.Radiobutton(mode_frame, text="ECB", variable=self.mode_var, value='ECB', command=self._update_iv_state).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(mode_frame, text="CBC", variable=self.mode_var, value='CBC', command=self._update_iv_state).pack(side=tk.LEFT)
        mode_frame.grid(row=2, column=1, sticky=tk.W)

        # 4. 输入数据 (十六进制)
        ttk.Label(main_frame, text="输入数据 (Hex):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.input_text = scrolledtext.ScrolledText(main_frame, width=50, height=8)
        self.input_text.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # 5. 操作按钮
        button_frame = ttk.Frame(main_frame)
        ttk.Button(button_frame, text="加密 (Encrypt)", command=lambda: self.run_process('encrypt')).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="解密 (Decrypt)", command=lambda: self.run_process('decrypt')).pack(side=tk.LEFT)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)

        # 6. 输出结果 (十六进制)
        ttk.Label(main_frame, text="输出结果 (Hex):").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.output_text = scrolledtext.ScrolledText(main_frame, width=50, height=8, state='disabled')
        self.output_text.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # 7. 状态栏
        self.status_label = ttk.Label(main_frame, text="准备就绪。数据长度必须是 16 字节的倍数。", foreground="blue")
        self.status_label.grid(row=8, column=0, columnspan=2, sticky=tk.W, pady=5)

        # 初始 IV 状态更新
        self._update_iv_state()

    def _update_iv_state(self):
        """根据模式启用或禁用 IV 输入框"""
        if self.mode_var.get() == 'ECB':
            self.iv_entry.config(state='disabled')
            self.status_label.config(text="当前模式：ECB (无需 IV)。数据长度必须是 16 字节的倍数。", foreground="blue")
        else:
            self.iv_entry.config(state='enabled')
            self.status_label.config(text="当前模式：CBC (需要 IV)。数据长度必须是 16 字节的倍数。", foreground="darkgreen")

    def run_process(self, action):
        """获取输入并调用核心处理函数"""
        # 清理并获取输入
        data = self.input_text.get("1.0", tk.END).replace('\n', '').strip()
        key = self.key_entry.get().strip()
        iv = self.iv_entry.get().strip()
        mode = self.mode_var.get()
        
        # 清空输出区
        self.output_text.config(state='normal')
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state='disabled')
        self.status_label.config(text="正在处理...", foreground="orange")
        self.master.update()

        # 调用核心 SM4 逻辑
        success, result = SM4Processor.process_sm4(data, key, iv, mode, action)

        # 显示结果
        if success:
            self.output_text.config(state='normal')
            self.output_text.insert(tk.END, result)
            self.output_text.config(state='disabled')
            self.status_label.config(text=f"操作成功！({action})", foreground="green")
        else:
            messagebox.showerror("处理错误", result)
            self.status_label.config(text=f"操作失败：{result}", foreground="red")


if __name__ == "__main__":
    root = tk.Tk()
    app = SM4App(root)
    root.mainloop()