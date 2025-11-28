import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import binascii
import base64
import os
import json
from datetime import datetime
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl import sm3, func

class SM4WithMACApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SM4加密与4字节MAC工具 (NoPad模式，十六进制密钥)")
        self.root.geometry("950x700")
        self.root.minsize(800, 600)
        self.root.resizable(True, True)
        
        # 首先初始化所有变量
        self.initialize_variables()
        
        # 然后设置样式
        self.setup_styles()
        
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建标签页
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建各个标签页
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_settings_tab()
        self.create_about_tab()
        
        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def initialize_variables(self):
        """初始化所有变量"""
        # 默认密钥现在使用十六进制字符串 (16字节 = 32个十六进制字符)
        self.default_key_hex = "1234567890abcdef1234567890abcdef"  # 32个十六进制字符
        self.mac_key_hex = "fedcba0987654321fedcba0987654321"      # 32个十六进制字符
        self.block_size = 16  # SM4块大小(16字节)
        
        # 加密/解密页面的变量
        self.encrypt_key_var = None
        self.mac_key_var = None
        self.input_format = None
        self.output_format = None
        self.encrypt_input = None
        self.encrypt_output = None
        self.mac_value = None
        
        # MAC相关
        self.mac_status = None
        self.verify_status = None
        self.integrity_status = None
        
        # 日志设置
        self.enable_logging = tk.BooleanVar(value=True)
    
    def setup_styles(self):
        """设置界面样式"""
        self.style = ttk.Style()
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        self.style.configure('Success.TLabel', foreground='green')
        self.style.configure('Warning.TLabel', foreground='orange')
        self.style.configure('Error.TLabel', foreground='red')
        self.style.configure('Info.TLabel', foreground='blue')
        
        try:
            # 尝试添加强调按钮样式
            self.style.configure('Accent.TButton', font=('Arial', 10, 'bold'), foreground='white', background='#4CAF50')
        except:
            pass  # 如果不支持自定义样式，使用默认按钮
        
        # 为不同标签页设置背景色
        self.style.configure('Encrypt.TFrame', background='#e8f4e8')
        self.style.configure('Decrypt.TFrame', background='#f4e8e8')
        self.style.configure('Settings.TFrame', background='#e8f0f8')
    
    def is_valid_hex_key(self, hex_string, key_name="密钥"):
        """验证十六进制密钥是否有效"""
        # 移除空格并转为小写
        hex_string = hex_string.replace(" ", "").lower()
        
        # 检查是否为有效的十六进制字符串
        if not all(c in '0123456789abcdef' for c in hex_string):
            messagebox.showerror("密钥错误", f"{key_name}包含无效的十六进制字符！\n只允许使用0-9和a-f。")
            return False
        
        # 检查长度 (16字节密钥 = 32个十六进制字符)
        if len(hex_string) != 32:  # 16字节 * 2 = 32个十六进制字符
            messagebox.showerror("密钥错误", 
                               f"{key_name}长度错误！\n必须是32个十六进制字符 (16字节)。\n当前长度: {len(hex_string)}个字符")
            return False
        
        return True
    
    def hex_to_bytes(self, hex_string):
        """将十六进制字符串转换为字节，移除空格并验证"""
        clean_hex = hex_string.replace(" ", "").lower()
        return bytes.fromhex(clean_hex)
    
    def format_hex_string(self, hex_string):
        """格式化十六进制字符串，每2个字符加一个空格，每16个字符换行"""
        clean_hex = hex_string.replace(" ", "").lower()
        # 每2个字符(1字节)加空格
        spaced = ' '.join(clean_hex[i:i+2] for i in range(0, len(clean_hex), 2))
        # 每16个字符(8字节)换行
        lines = []
        for i in range(0, len(spaced), 48):  # 16字节 * 3字符(2字符+1空格) = 48
            lines.append(spaced[i:i+48])
        return '\n'.join(lines)
    
    def create_encrypt_tab(self):
        """创建加密标签页，使用十六进制密钥输入"""
        encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(encrypt_frame, text="加密 & 生成MAC")
        
        # 密钥设置
        key_frame = ttk.LabelFrame(encrypt_frame, text="密钥设置 (16字节/128位，十六进制格式)", padding=10)
        key_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # 加密密钥
        ttk.Label(key_frame, text="加密密钥 (32个十六进制字符):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.encrypt_key_var = tk.StringVar(value=self.default_key_hex)
        encrypt_key_entry = ttk.Entry(key_frame, textvariable=self.encrypt_key_var, width=40)
        encrypt_key_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(key_frame, text="验证", command=lambda: self.validate_single_key(self.encrypt_key_var, "加密密钥")).grid(row=0, column=2, padx=5, pady=5)
        
        # MAC密钥
        ttk.Label(key_frame, text="MAC密钥 (32个十六进制字符):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.mac_key_var = tk.StringVar(value=self.mac_key_hex)
        mac_key_entry = ttk.Entry(key_frame, textvariable=self.mac_key_var, width=40)
        mac_key_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(key_frame, text="验证", command=lambda: self.validate_single_key(self.mac_key_var, "MAC密钥")).grid(row=1, column=2, padx=5, pady=5)
        
        # 密钥操作按钮
        key_btn_frame = ttk.Frame(key_frame)
        key_btn_frame.grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=5)
        ttk.Button(key_btn_frame, text="生成随机密钥", command=self.generate_random_hex_keys).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_btn_frame, text="验证所有密钥", command=self.validate_keys).pack(side=tk.LEFT, padx=5)
        
        # 输入数据
        input_frame = ttk.LabelFrame(encrypt_frame, text="输入数据 (必须是16字节的倍数)", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 数据格式选择
        format_frame = ttk.Frame(input_frame)
        format_frame.pack(fill=tk.X, pady=5)
        
        self.input_format = tk.StringVar(value="text")
        ttk.Label(format_frame, text="输入格式:").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="文本", variable=self.input_format, value="text").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="十六进制", variable=self.input_format, value="hex").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="Base64", variable=self.input_format, value="base64").pack(side=tk.LEFT, padx=5)
        ttk.Button(format_frame, text="从文件加载", command=lambda: self.load_file(input_frame)).pack(side=tk.RIGHT, padx=5)
        
        # 输入文本框
        self.encrypt_input = scrolledtext.ScrolledText(input_frame, height=8, font=('Consolas', 10))
        self.encrypt_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.encrypt_input.insert(tk.END, "请输入要加密的数据 (长度必须是16字节的倍数)")
        
        # 操作按钮
        btn_frame = ttk.Frame(encrypt_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.encrypt_btn = ttk.Button(btn_frame, text="加密并生成4字节MAC", command=self.encrypt_with_mac)
        self.encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="清除", command=lambda: self.clear_text(self.encrypt_input)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="示例", command=self.load_encrypt_example).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="保存结果", command=self.save_encrypt_result).pack(side=tk.RIGHT, padx=5)
        
        # 输出结果
        output_frame = ttk.LabelFrame(encrypt_frame, text="加密结果与4字节MAC", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 输出格式选择
        out_format_frame = ttk.Frame(output_frame)
        out_format_frame.pack(fill=tk.X, pady=5)
        
        self.output_format = tk.StringVar(value="hex")
        ttk.Label(out_format_frame, text="输出格式:").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(out_format_frame, text="十六进制", variable=self.output_format, value="hex").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(out_format_frame, text="Base64", variable=self.output_format, value="base64").pack(side=tk.LEFT, padx=5)
        
        # 输出文本框
        self.encrypt_output = scrolledtext.ScrolledText(output_frame, height=10, font=('Consolas', 10), state=tk.DISABLED)
        self.encrypt_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # MAC显示
        mac_frame = ttk.Frame(output_frame)
        mac_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(mac_frame, text="4字节MAC:").pack(side=tk.LEFT, padx=5)
        self.mac_value = tk.StringVar()
        mac_entry = ttk.Entry(mac_frame, textvariable=self.mac_value, width=20, state=tk.DISABLED)
        mac_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(mac_frame, text="MAC验证:").pack(side=tk.LEFT, padx=15)
        self.mac_status = ttk.Label(mac_frame, text="未验证", style='Warning.TLabel')
        self.mac_status.pack(side=tk.LEFT, padx=5)
    
    def create_decrypt_tab(self):
        """创建解密标签页，使用十六进制密钥输入"""
        decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(decrypt_frame, text="解密 & 验证MAC")
        
        # 密钥设置
        key_frame = ttk.LabelFrame(decrypt_frame, text="密钥设置 (16字节/128位，十六进制格式)", padding=10)
        key_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # 加密密钥
        ttk.Label(key_frame, text="加密密钥 (32个十六进制字符):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.decrypt_key_var = tk.StringVar(value=self.default_key_hex)
        decrypt_key_entry = ttk.Entry(key_frame, textvariable=self.decrypt_key_var, width=40)
        decrypt_key_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(key_frame, text="验证", command=lambda: self.validate_single_key(self.decrypt_key_var, "解密密钥")).grid(row=0, column=2, padx=5, pady=5)
        
        # MAC密钥
        ttk.Label(key_frame, text="MAC密钥 (32个十六进制字符):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.decrypt_mac_key_var = tk.StringVar(value=self.mac_key_hex)
        decrypt_mac_key_entry = ttk.Entry(key_frame, textvariable=self.decrypt_mac_key_var, width=40)
        decrypt_mac_key_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(key_frame, text="验证", command=lambda: self.validate_single_key(self.decrypt_mac_key_var, "MAC密钥")).grid(row=1, column=2, padx=5, pady=5)
        
        # 密钥同步按钮
        ttk.Button(key_frame, text="同步加密页密钥", command=self.sync_keys).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # 输入数据
        input_frame = ttk.LabelFrame(decrypt_frame, text="加密数据与MAC", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 数据格式选择
        format_frame = ttk.Frame(input_frame)
        format_frame.pack(fill=tk.X, pady=5)
        
        self.decrypt_input_format = tk.StringVar(value="hex")
        ttk.Label(format_frame, text="输入格式:").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="十六进制", variable=self.decrypt_input_format, value="hex").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="Base64", variable=self.decrypt_input_format, value="base64").pack(side=tk.LEFT, padx=5)
        ttk.Button(format_frame, text="从文件加载", command=lambda: self.load_file(input_frame, is_decrypt=True)).pack(side=tk.RIGHT, padx=5)
        
        # 输入文本框
        self.decrypt_input = scrolledtext.ScrolledText(input_frame, height=8, font=('Consolas', 10))
        self.decrypt_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # MAC输入
        mac_frame = ttk.Frame(input_frame)
        mac_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(mac_frame, text="4字节MAC (十六进制):").pack(side=tk.LEFT, padx=5)
        self.input_mac_var = tk.StringVar()
        mac_entry = ttk.Entry(mac_frame, textvariable=self.input_mac_var, width=20)
        mac_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(mac_frame, text="从加密结果复制", command=self.copy_mac_from_encrypt).pack(side=tk.LEFT, padx=10)
        
        # 操作按钮
        btn_frame = ttk.Frame(decrypt_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.decrypt_btn = ttk.Button(btn_frame, text="解密并验证MAC", command=self.decrypt_and_verify)
        self.decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="清除", command=lambda: self.clear_text(self.decrypt_input)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="示例", command=self.load_decrypt_example).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="保存结果", command=self.save_decrypt_result).pack(side=tk.RIGHT, padx=5)
        
        # 输出结果
        output_frame = ttk.LabelFrame(decrypt_frame, text="解密结果", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 验证状态
        verify_frame = ttk.Frame(output_frame)
        verify_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(verify_frame, text="MAC验证状态:").pack(side=tk.LEFT, padx=5)
        self.verify_status = ttk.Label(verify_frame, text="未验证", style='Warning.TLabel')
        self.verify_status.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(verify_frame, text="数据完整性:").pack(side=tk.LEFT, padx=15)
        self.integrity_status = ttk.Label(verify_frame, text="未知", style='Warning.TLabel')
        self.integrity_status.pack(side=tk.LEFT, padx=5)
        
        # 输出文本框
        self.decrypt_output = scrolledtext.ScrolledText(output_frame, height=10, font=('Consolas', 10), state=tk.DISABLED)
        self.decrypt_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_settings_tab(self):
        """创建设置标签页"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="设置")
        
        # 安全设置
        security_frame = ttk.LabelFrame(settings_frame, text="安全设置", padding=10)
        security_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(security_frame, text="MAC长度:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.mac_length = tk.IntVar(value=4)
        mac_length_spin = ttk.Spinbox(security_frame, from_=4, to=32, textvariable=self.mac_length, width=5)
        mac_length_spin.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(security_frame, text="字节 (默认4字节)").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # 注意：4字节MAC安全性较低，添加警告
        warning_label = ttk.Label(security_frame, 
                                text="警告: 4字节MAC安全性较低，仅适用于资源受限环境。生产环境建议使用16字节或更长。",
                                wraplength=500, justify=tk.LEFT, style='Error.TLabel')
        warning_label.grid(row=1, column=0, columnspan=3, sticky=tk.W, padx=5, pady=10)
        
        # 高级设置
        advanced_frame = ttk.LabelFrame(settings_frame, text="高级设置", padding=10)
        advanced_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(advanced_frame, text="加密模式:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.encrypt_mode = tk.StringVar(value="ecb")
        ttk.Radiobutton(advanced_frame, text="ECB (默认)", variable=self.encrypt_mode, value="ecb").grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Radiobutton(advanced_frame, text="CBC", variable=self.encrypt_mode, value="cbc").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # 密钥格式设置
        key_format_frame = ttk.LabelFrame(settings_frame, text="密钥格式设置", padding=10)
        key_format_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(key_format_frame, text="当前密钥格式:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Label(key_format_frame, text="十六进制 (32个字符)", font=('Arial', 10, 'bold'), foreground='blue').grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # 密钥格式说明
        info_text = """
        密钥格式说明:
        - SM4算法使用16字节(128位)密钥
        - 十六进制格式: 32个十六进制字符 (0-9, a-f)
        - 例如: 1234567890abcdef1234567890abcdef
        - 每2个十六进制字符表示1个字节
        """
        ttk.Label(key_format_frame, text=info_text, justify=tk.LEFT).grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=(0,10))        
        # 日志设置
        log_frame = ttk.LabelFrame(settings_frame, text="日志设置", padding=10)
        log_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Checkbutton(log_frame, text="启用操作日志", variable=self.enable_logging).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        ttk.Button(log_frame, text="查看日志文件", command=self.view_log_file).grid(row=0, column=1, padx=10, pady=5)
        ttk.Button(log_frame, text="清除日志", command=self.clear_log_file).grid(row=0, column=2, padx=5, pady=5)
    
    def create_about_tab(self):
        """创建关于标签页"""
        about_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_frame, text="关于")
        
        # 应用信息
        info_frame = ttk.LabelFrame(about_frame, text="应用信息", padding=15)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        ttk.Label(info_frame, text="SM4加密与4字节MAC工具", font=('Arial', 14, 'bold')).pack(pady=10)
        ttk.Label(info_frame, text="版本: 1.1.0 (十六进制密钥输入版)", font=('Arial', 10)).pack(pady=5)
        ttk.Label(info_frame, text="基于gmssl库实现", font=('Arial', 10)).pack(pady=5)
        ttk.Label(info_frame, text="支持SM4加密算法(NoPad模式)和4字节MAC", font=('Arial', 10)).pack(pady=5)
        
        # 使用说明
        ttk.Label(info_frame, text="使用说明:", font=('Arial', 10, 'bold'), anchor=tk.W).pack(fill=tk.X, pady=(15, 5))
        instructions = """
1. 密钥输入:
   - 所有密钥必须为32个十六进制字符 (16字节)
   - 例如: 1234567890abcdef1234567890abcdef
   - 只允许使用0-9和a-f字符

2. 加密标签页:
   - 输入16字节密钥(十六进制格式)
   - 输入要加密的数据(长度必须是16字节的倍数)
   - 点击"加密并生成4字节MAC"按钮

3. 解密标签页:
   - 使用相同的密钥(十六进制格式)
   - 粘贴加密数据和4字节MAC
   - 点击"解密并验证MAC"按钮

注意: 4字节MAC安全性较低，仅适用于资源受限环境。
        """
        ttk.Label(info_frame, text=instructions, justify=tk.LEFT, font=('Arial', 9)).pack(pady=5)
        
        # 作者信息
        ttk.Label(info_frame, text="© 2024 SM4加密工具", font=('Arial', 9)).pack(pady=(20, 5))
    
    def generate_random_hex_keys(self):
        """生成随机十六进制密钥"""
        import random
        
        # 生成16字节随机密钥 (32个十六进制字符)
        hex_chars = '0123456789abcdef'
        encrypt_key = ''.join(random.choice(hex_chars) for _ in range(32))
        mac_key = ''.join(random.choice(hex_chars) for _ in range(32))
        
        self.encrypt_key_var.set(encrypt_key)
        self.mac_key_var.set(mac_key)
        self.decrypt_key_var.set(encrypt_key)
        self.decrypt_mac_key_var.set(mac_key)
        
        self.status_var.set("已生成随机十六进制密钥")
        self.log_operation("密钥生成", "成功生成随机十六进制加密密钥和MAC密钥")
    
    def validate_single_key(self, key_var, key_name):
        """验证单个密钥"""
        key_hex = key_var.get()
        if self.is_valid_hex_key(key_hex, key_name):
            messagebox.showinfo("密钥验证", f"{key_name}验证成功！\n是有效的32个十六进制字符。")
            return True
        return False
    
    def validate_keys(self):
        """验证所有密钥"""
        encrypt_key = self.encrypt_key_var.get()
        mac_key = self.mac_key_var.get()
        
        if not self.is_valid_hex_key(encrypt_key, "加密密钥"):
            return False
        
        if not self.is_valid_hex_key(mac_key, "MAC密钥"):
            return False
        
        messagebox.showinfo("验证成功", "所有密钥验证通过！\n加密密钥和MAC密钥均为有效的32个十六进制字符。")
        self.status_var.set("所有密钥验证成功")
        return True
    
    def load_file(self, parent_frame, is_decrypt=False):
        """从文件加载数据"""
        file_path = filedialog.askopenfilename(
            title="选择文件",
            filetypes=[("所有文件", "*.*"), ("文本文件", "*.txt"), ("二进制文件", "*.bin")]
        )
        
        if not file_path:
            return
        
        try:
            # 读取文件内容
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # 根据格式转换
            data_format = self.input_format.get() if not is_decrypt else self.decrypt_input_format.get()
            
            if data_format == "hex":
                file_content = binascii.hexlify(content).decode('utf-8')
            elif data_format == "base64":
                file_content = base64.b64encode(content).decode('utf-8')
            else:  # text
                try:
                    file_content = content.decode('utf-8')
                except UnicodeDecodeError:
                    # 如果不是文本，提示用户
                    if messagebox.askyesno("格式转换", "文件不是有效文本，是否以十六进制格式加载？"):
                        file_content = binascii.hexlify(content).decode('utf-8')
                        if not is_decrypt:
                            self.input_format.set("hex")
                        else:
                            self.decrypt_input_format.set("hex")
                    else:
                        return
            
            # 设置到文本框
            if not is_decrypt:
                self.encrypt_input.delete(1.0, tk.END)
                self.encrypt_input.insert(tk.END, file_content)
            else:
                self.decrypt_input.delete(1.0, tk.END)
                self.decrypt_input.insert(tk.END, file_content)
            
            self.status_var.set(f"已从文件加载: {os.path.basename(file_path)}")
            self.log_operation("文件加载", f"成功加载文件: {file_path}")
            
        except Exception as e:
            messagebox.showerror("文件错误", f"加载文件失败: {str(e)}")
            self.status_var.set(f"文件加载失败: {str(e)}")
    
    def load_encrypt_example(self):
        """加载加密示例，使用十六进制密钥"""
        # 设置示例密钥 (十六进制格式)
        self.encrypt_key_var.set("1234567890abcdef1234567890abcdef")  # 16字节密钥的十六进制表示
        self.mac_key_var.set("fedcba0987654321fedcba0987654321")      # 16字节密钥的十六进制表示
        
        # 设置示例数据 (16字节)
        example_data = "HelloWorld123456"  # 正好16字节
        self.encrypt_input.delete(1.0, tk.END)
        self.encrypt_input.insert(tk.END, example_data)
        
        self.status_var.set("已加载加密示例")
    
    def load_decrypt_example(self):
        """加载解密示例，使用十六进制密钥"""
        # 同步密钥
        self.decrypt_key_var.set("1234567890abcdef1234567890abcdef")
        self.decrypt_mac_key_var.set("fedcba0987654321fedcba0987654321")
        
        # 示例加密数据 (使用上面示例加密后的结果，十六进制格式)
        example_encrypted = "b6a8c3d51d4f7e9a2c6b8d0e4f1a3c5b9a8d7e6f5c4b3a2d1e0f9c8b7a6d5e4f"  # 示例十六进制数据
        self.decrypt_input.delete(1.0, tk.END)
        self.decrypt_input.insert(tk.END, example_encrypted)
        
        # 示例MAC
        self.input_mac_var.set("a1b2c3d4")  # 示例4字节MAC
        
        self.status_var.set("已加载解密示例")
    
    def clear_text(self, text_widget):
        """清除文本框内容"""
        text_widget.delete(1.0, tk.END)
    
    def sync_keys(self):
        """同步加密页的密钥到解密页"""
        self.decrypt_key_var.set(self.encrypt_key_var.get())
        self.decrypt_mac_key_var.set(self.mac_key_var.get())
        self.status_var.set("密钥已同步")
    
    def copy_mac_from_encrypt(self):
        """从加密结果复制MAC"""
        mac_value = self.mac_value.get()
        if mac_value:
            self.input_mac_var.set(mac_value)
            self.status_var.set("MAC已复制到解密页")
        else:
            messagebox.showwarning("警告", "加密页没有有效的MAC值")
    
    def encrypt_with_mac(self):
        """执行加密并生成4字节MAC，使用十六进制密钥"""
        try:
            # 验证密钥
            if not self.validate_keys():
                return
            
            # 获取输入数据
            input_data = self.encrypt_input.get(1.0, tk.END).strip()
            if not input_data:
                messagebox.showwarning("输入错误", "请输入要加密的数据")
                return
            
            # 转换输入数据为字节
            data_bytes = self.convert_to_bytes(input_data, self.input_format.get())
            
            # 检查数据长度 (NoPad模式要求16字节倍数)
            if len(data_bytes) % self.block_size != 0:
                raise ValueError(f"数据长度必须是{self.block_size}字节的倍数 (当前长度: {len(data_bytes)} 字节)")
            
            # 获取密钥 (从十六进制字符串转为字节)
            encrypt_key_hex = self.encrypt_key_var.get().replace(" ", "")
            mac_key_hex = self.mac_key_var.get().replace(" ", "")
            
            encrypt_key = self.hex_to_bytes(encrypt_key_hex)
            mac_key = self.hex_to_bytes(mac_key_hex)
            
            # 执行SM4加密
            crypt_sm4 = CryptSM4()
            crypt_sm4.set_key(encrypt_key, SM4_ENCRYPT)
            
            # 根据模式选择加密方式
            mode = self.encrypt_mode.get()
            if mode == "ecb":
                encrypted_data = crypt_sm4.crypt_ecb(data_bytes)
            else:  # cbc
                iv = b'\x00' * 16  # 使用零向量作为IV (实际应用中应使用随机IV)
                encrypted_data = crypt_sm4.crypt_cbc(iv, data_bytes)
            
            # 生成4字节MAC
            mac = self.generate_4byte_mac(data_bytes, mac_key)
            
            # 转换为输出格式
            output_format = self.output_format.get()
            if output_format == "hex":
                output_data = binascii.hexlify(encrypted_data).decode('utf-8')
            else:  # base64
                output_data = base64.b64encode(encrypted_data).decode('utf-8')
            
            # 显示结果
            self.encrypt_output.config(state=tk.NORMAL)
            self.encrypt_output.delete(1.0, tk.END)
            self.encrypt_output.insert(tk.END, output_data)
            self.encrypt_output.config(state=tk.DISABLED)
            
            # 显示MAC
            self.mac_value.set(binascii.hexlify(mac).decode('utf-8').lower())
            self.mac_status.config(text="已生成", style='Success.TLabel')
            
            # 更新状态
            self.status_var.set(f"加密成功! 数据长度: {len(data_bytes)} 字节, 密文长度: {len(encrypted_data)} 字节")
            self.log_operation("加密操作", f"成功加密 {len(data_bytes)} 字节数据，使用十六进制密钥")
            
        except Exception as e:
            error_msg = f"加密失败: {str(e)}"
            messagebox.showerror("加密错误", error_msg)
            self.status_var.set(error_msg)
            self.log_operation("加密错误", error_msg)
    
    def decrypt_and_verify(self):
        """执行解密并验证MAC，使用十六进制密钥"""
        try:
            # 验证密钥
            decrypt_key_hex = self.decrypt_key_var.get().replace(" ", "")
            mac_key_hex = self.decrypt_mac_key_var.get().replace(" ", "")
            
            if not self.is_valid_hex_key(decrypt_key_hex, "解密密钥"):
                return
            
            if not self.is_valid_hex_key(mac_key_hex, "MAC密钥"):
                return
            
            # 获取输入数据
            input_data = self.decrypt_input.get(1.0, tk.END).strip()
            if not input_data:
                messagebox.showwarning("输入错误", "请输入要解密的数据")
                return
            
            # 获取MAC
            mac_hex = self.input_mac_var.get().strip()
            if not mac_hex:
                messagebox.showwarning("输入错误", "请输入4字节MAC值")
                return
            
            if len(mac_hex) != 8:  # 4字节 = 8个十六进制字符
                raise ValueError(f"MAC长度错误，4字节MAC应为8个十六进制字符，当前: {len(mac_hex)}")
            
            # 转换输入数据为字节
            encrypted_data = self.convert_from_format(input_data, self.decrypt_input_format.get())
            
            # 转换MAC为字节
            try:
                mac_bytes = bytes.fromhex(mac_hex)
                if len(mac_bytes) != 4:
                    raise ValueError("MAC转换失败，长度不为4字节")
            except Exception as e:
                raise ValueError(f"MAC格式错误: {str(e)}")
            
            # 检查密文长度 (应为16字节倍数)
            if len(encrypted_data) % self.block_size != 0:
                raise ValueError(f"密文长度必须是{self.block_size}字节的倍数 (当前长度: {len(encrypted_data)} 字节)")
            
            # 获取密钥 (从十六进制字符串转为字节)
            decrypt_key = self.hex_to_bytes(decrypt_key_hex)
            mac_key = self.hex_to_bytes(mac_key_hex)
            
            # 执行SM4解密
            crypt_sm4 = CryptSM4()
            crypt_sm4.set_key(decrypt_key, SM4_DECRYPT)
            
            # 根据模式选择解密方式
            mode = self.encrypt_mode.get()
            if mode == "ecb":
                decrypted_data = crypt_sm4.crypt_ecb(encrypted_data)
            else:  # cbc
                iv = b'\x00' * 16  # 使用零向量作为IV
                decrypted_data = crypt_sm4.crypt_cbc(iv, encrypted_data)
            
            # 验证MAC
            calculated_mac = self.generate_4byte_mac(decrypted_data, mac_key)
            is_valid = calculated_mac == mac_bytes
            
            # 显示解密结果
            try:
                # 尝试作为文本解码
                output_text = decrypted_data.decode('utf-8')
            except UnicodeDecodeError:
                # 如果不是有效UTF-8，显示为十六进制
                output_text = binascii.hexlify(decrypted_data).decode('utf-8')
            
            self.decrypt_output.config(state=tk.NORMAL)
            self.decrypt_output.delete(1.0, tk.END)
            self.decrypt_output.insert(tk.END, output_text)
            self.decrypt_output.config(state=tk.DISABLED)
            
            # 更新验证状态
            if is_valid:
                self.verify_status.config(text="有效", style='Success.TLabel')
                self.integrity_status.config(text="完整", style='Success.TLabel')
                status_msg = "MAC验证成功! 数据完整无篡改"
            else:
                self.verify_status.config(text="无效", style='Error.TLabel')
                self.integrity_status.config(text="可能被篡改", style='Error.TLabel')
                status_msg = "警告: MAC验证失败! 数据可能被篡改"
            
            # 更新状态
            self.status_var.set(f"解密完成! 原始数据长度: {len(decrypted_data)} 字节. {status_msg}")
            self.log_operation("解密操作", 
                              f"{'成功' if is_valid else '警告'}: 解密 {len(decrypted_data)} 字节数据, MAC验证{'' if is_valid else '未'}通过")
            
            if not is_valid:
                messagebox.showwarning("MAC验证失败", 
                                     "MAC验证失败! 数据可能已被篡改。\n请检查密钥是否正确，或数据是否被修改。")
            
        except Exception as e:
            error_msg = f"解密失败: {str(e)}"
            messagebox.showerror("解密错误", error_msg)
            self.status_var.set(error_msg)
            self.log_operation("解密错误", error_msg)
    
    def generate_4byte_mac(self, data, key):
        """生成4字节MAC - 使用SM4 CBC模式实现"""
        # 方法: 使用SM4 CBC模式加密数据，然后截取结果的前4字节
        # CBC模式使用零向量作为初始化向量(IV)
        
        # 确保数据是16字节的倍数 (CBC模式要求块对齐)
        if len(data) % 16 != 0:
            # 不足16字节倍数，用零填充到16字节倍数
            padding_len = 16 - (len(data) % 16)
            mac_input = data + b'\x00' * padding_len
        else:
            mac_input = data
        
        # 使用SM4 CBC模式加密数据
        # IV使用全零向量 (标准MAC实现)
        iv = b'\x00' * 16
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(key, SM4_ENCRYPT)
        encrypted = crypt_sm4.crypt_cbc(iv, mac_input)
        
        # 取最后一块密文的前4字节作为MAC
        # CBC模式的最后一块包含了整个消息的验证信息
        mac_bytes = encrypted[-16:-12]  # 最后一块的前4字节
        return mac_bytes
    
    def convert_to_bytes(self, input_str, data_format):
        """将输入字符串转换为字节"""
        try:
            if data_format == "hex":
                # 移除空格和换行
                clean_str = input_str.replace(' ', '').replace('\n', '').replace('\r', '')
                return bytes.fromhex(clean_str)
            elif data_format == "base64":
                return base64.b64decode(input_str)
            else:  # text
                return input_str.encode('utf-8')
        except Exception as e:
            raise ValueError(f"数据格式转换失败 ({data_format}): {str(e)}")
    
    def convert_from_format(self, input_str, data_format):
        """从指定格式转换为字节"""
        try:
            if data_format == "hex":
                clean_str = input_str.replace(' ', '').replace('\n', '').replace('\r', '')
                return bytes.fromhex(clean_str)
            elif data_format == "base64":
                return base64.b64decode(input_str)
            else:  # text (不太可能，因为加密数据通常不是文本)
                return input_str.encode('utf-8')
        except Exception as e:
            raise ValueError(f"数据格式转换失败 ({data_format}): {str(e)}")
    
    def save_encrypt_result(self):
        """保存加密结果"""
        encrypted_data = self.encrypt_output.get(1.0, tk.END).strip()
        mac_value = self.mac_value.get()
        
        if not encrypted_data or not mac_value:
            messagebox.showwarning("保存错误", "没有可保存的加密结果")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".bin",
            filetypes=[("二进制文件", "*.bin"), ("文本文件", "*.txt"), ("所有文件", "*.*")],
            title="保存加密结果"
        )
        
        if not file_path:
            return
        
        try:
            # 根据格式准备数据
            output_format = self.output_format.get()
            if output_format == "hex":
                data_bytes = bytes.fromhex(encrypted_data.replace(' ', '').replace('\n', ''))
            else:  # base64
                data_bytes = base64.b64decode(encrypted_data)
            
            # 保存加密数据和MAC
            with open(file_path, 'wb') as f:
                f.write(data_bytes)
            
            # 保存MAC到单独文件
            mac_file = os.path.splitext(file_path)[0] + "_mac.txt"
            with open(mac_file, 'w') as f:
                f.write(f"4字节MAC (十六进制): {mac_value}\n")
                f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"数据长度: {len(data_bytes)} 字节\n")
                f.write(f"使用的密钥 (示例):\n")
                f.write(f"  加密密钥: {self.encrypt_key_var.get()}\n")
                f.write(f"  MAC密钥: {self.mac_key_var.get()}\n")
            
            self.status_var.set(f"结果已保存到: {file_path} 和 {mac_file}")
            self.log_operation("结果保存", f"加密结果保存到 {file_path}")
            messagebox.showinfo("保存成功", f"加密数据已保存到:\n{file_path}\n\nMAC值已保存到:\n{mac_file}")
            
        except Exception as e:
            error_msg = f"保存失败: {str(e)}"
            messagebox.showerror("保存错误", error_msg)
            self.status_var.set(error_msg)
    
    def save_decrypt_result(self):
        """保存解密结果"""
        decrypted_data = self.decrypt_output.get(1.0, tk.END).strip()
        
        if not decrypted_data:
            messagebox.showwarning("保存错误", "没有可保存的解密结果")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            title="保存解密结果"
        )
        
        if not file_path:
            return
        
        try:
            # 尝试保存为文本
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(decrypted_data)
            
            self.status_var.set(f"解密结果已保存到: {file_path}")
            self.log_operation("结果保存", f"解密结果保存到 {file_path}")
            messagebox.showinfo("保存成功", f"解密结果已保存到:\n{file_path}")
            
        except Exception as e:
            # 如果文本保存失败，尝试作为二进制保存
            try:
                # 尝试将内容作为十六进制数据
                clean_data = decrypted_data.replace(' ', '').replace('\n', '')
                data_bytes = bytes.fromhex(clean_data)
                
                bin_file = os.path.splitext(file_path)[0] + ".bin"
                with open(bin_file, 'wb') as f:
                    f.write(data_bytes)
                
                self.status_var.set(f"二进制结果已保存到: {bin_file}")
                self.log_operation("结果保存", f"二进制解密结果保存到 {bin_file}")
                messagebox.showinfo("保存成功", f"二进制数据已保存到:\n{bin_file}")
                
            except Exception as e2:
                error_msg = f"保存失败: {str(e)}\n尝试二进制保存也失败: {str(e2)}"
                messagebox.showerror("保存错误", error_msg)
                self.status_var.set(error_msg)
    
    def log_operation(self, operation, details):
        """记录操作日志"""
        if not self.enable_logging.get():
            return
        
        log_file = "sm4_tool.log"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {operation}: {details}\n")
        except Exception as e:
            print(f"日志记录失败: {str(e)}")
    
    def view_log_file(self):
        """查看日志文件"""
        log_file = "sm4_tool.log"
        
        if not os.path.exists(log_file):
            messagebox.showinfo("日志文件", "日志文件不存在，尚未有操作记录。")
            return
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
            
            # 创建日志查看窗口
            log_window = tk.Toplevel(self.root)
            log_window.title("操作日志")
            log_window.geometry("800x600")
            
            log_text = scrolledtext.ScrolledText(log_window, font=('Consolas', 10))
            log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            log_text.insert(tk.END, log_content)
            log_text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("日志错误", f"读取日志文件失败: {str(e)}")
    
    def clear_log_file(self):
        """清除日志文件"""
        log_file = "sm4_tool.log"
        
        if not os.path.exists(log_file):
            messagebox.showinfo("日志清除", "日志文件不存在，无需清除。")
            return
        
        if messagebox.askyesno("确认清除", "确定要清除所有操作日志吗？此操作不可恢复。"):
            try:
                open(log_file, 'w').close()  # 清空文件
                self.status_var.set("操作日志已清除")
                messagebox.showinfo("日志清除", "操作日志已成功清除。")
            except Exception as e:
                messagebox.showerror("日志错误", f"清除日志失败: {str(e)}")

if __name__ == "__main__":
    try:
        # 检查gmssl库是否安装
        try:
            from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
            from gmssl import sm3, func
        except ImportError:
            # 尝试安装gmssl
            import sys, subprocess
            if messagebox.askyesno("依赖缺失", "未找到gmssl库。是否自动安装？"):
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "gmssl"])
                    messagebox.showinfo("安装成功", "gmssl库已成功安装，请重新启动程序。")
                    sys.exit(0)
                except Exception as e:
                    messagebox.showerror("安装失败", 
                                       f"自动安装gmssl失败: {str(e)}\n\n请手动安装:\n"
                                       f"{sys.executable} -m pip install gmssl")
                    sys.exit(1)
        
        # 创建主窗口
        root = tk.Tk()
        
        # 设置主题 (如果支持)
        try:
            from ttkthemes import ThemedStyle
            style = ThemedStyle(root)
            style.set_theme("arc")  # 或 "breeze", "equilux" 等
        except ImportError:
            # 没有安装ttkthemes，使用默认主题
            pass
        
        # 创建应用
        app = SM4WithMACApp(root)
        
        # 运行主循环
        root.mainloop()
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        try:
            messagebox.showerror("致命错误", f"程序启动失败:\n{str(e)}\n\n{error_details}")
        except:
            print(f"致命错误: {str(e)}")
            print(error_details)