import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress
import re

# ========== IP地址计算器相关函数 ==========
def decimal_to_binary(ip):
    return '.'.join(f'{int(octet):08b}' for octet in ip.split('.'))

def binary_to_decimal(binary_str):
    return '.'.join(str(int(part, 2)) for part in binary_str.split('.'))

def is_valid_decimal(ip):
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not pattern.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

def is_valid_binary(ip):
    pattern = re.compile(r'^([01]{8}\.){3}[01]{8}$')
    return bool(pattern.match(ip))

def get_host_number_binary(network, host_number):
    host_bits = 32 - network.prefixlen
    host_bits_binary = f'{host_number:0{host_bits}b}'
    host_number_binary_full = '0' * network.prefixlen + host_bits_binary
    octets = [host_number_binary_full[i:i+8] for i in range(0, 32, 8)]
    return '.'.join(octets)

def get_network_class(ip):
    first_octet = int(ip.split('.')[0])
    if 1 <= first_octet <= 127:
        return "A类"
    elif 128 <= first_octet <= 191:
        return "B类"
    elif 192 <= first_octet <= 223:
        return "C类"
    elif 224 <= first_octet <= 239:
        return "D类（多播地址）"
    elif 240 <= first_octet <= 255:
        return "E类（实验地址）"
    return "未知类别"


def ip_calculator_frame(parent, on_action=None):
    frame = ttk.Frame(parent)
    ip_var = tk.StringVar()
    ip_converted_var = tk.StringVar()
    netmask_var = tk.StringVar()
    netmask_converted_var = tk.StringVar()
    network_info_var = tk.StringVar()
    network_info_binary_var = tk.StringVar()
    broadcast_info_var = tk.StringVar()
    broadcast_info_binary_var = tk.StringVar()
    network_class_var = tk.StringVar()
    first_available_ip_var = tk.StringVar()
    first_available_ip_binary_var = tk.StringVar()
    last_available_ip_var = tk.StringVar()
    last_available_ip_binary_var = tk.StringVar()
    restricted_broadcast_var = tk.StringVar()
    restricted_broadcast_binary_var = tk.StringVar()
    host_number_var = tk.StringVar()
    host_number_binary_var = tk.StringVar()

    def calculate_ip_info():
        try:
            ip_input = ip_var.get().strip()
            netmask_input = netmask_var.get().strip()
            if is_valid_decimal(ip_input):
                ip_decimal = ip_input
                ip_binary = decimal_to_binary(ip_decimal)
                input_format = 'decimal'
            elif is_valid_binary(ip_input):
                ip_decimal = binary_to_decimal(ip_input)
                ip_binary = ip_input
                input_format = 'binary'
            else:
                raise ValueError("IP地址格式不正确")
            if is_valid_decimal(netmask_input):
                netmask_decimal = netmask_input
                netmask_binary = decimal_to_binary(netmask_decimal)
                mask_format = 'decimal'
            elif is_valid_binary(netmask_input):
                netmask_decimal = binary_to_decimal(netmask_input)
                netmask_binary = netmask_input
                mask_format = 'binary'
            else:
                raise ValueError("子网掩码格式不正确")
            ip_converted_var.set(ip_binary if input_format == 'decimal' else ip_decimal)
            netmask_converted_var.set(netmask_binary if mask_format == 'decimal' else netmask_decimal)
            ip = ipaddress.IPv4Address(ip_decimal)
            netmask = ipaddress.IPv4Address(netmask_decimal)
            network = ipaddress.IPv4Network(f'{ip}/{netmask}', strict=False)
            network_address = str(network.network_address)
            broadcast_address = str(network.broadcast_address)
            first_host = str(next(network.hosts()))
            last_host = str(list(network.hosts())[-1])
            restricted_broadcast_address = "255.255.255.255"
            host_number = int(ip) - int(network.network_address)
            host_number_binary = get_host_number_binary(network, host_number)
            host_number_decimal_from_binary = binary_to_decimal(host_number_binary)
            network_info_var.set(network_address)
            network_info_binary_var.set(decimal_to_binary(network_address))
            broadcast_info_var.set(broadcast_address)
            broadcast_info_binary_var.set(decimal_to_binary(broadcast_address))
            network_class_var.set(get_network_class(str(network.network_address)))
            first_available_ip_var.set(first_host)
            first_available_ip_binary_var.set(decimal_to_binary(first_host))
            last_available_ip_var.set(last_host)
            last_available_ip_binary_var.set(decimal_to_binary(last_host))
            restricted_broadcast_var.set(restricted_broadcast_address)
            restricted_broadcast_binary_var.set(decimal_to_binary(restricted_broadcast_address))
            host_number_var.set(host_number_decimal_from_binary)
            host_number_binary_var.set(host_number_binary)
            if on_action:
                on_action({
                    'ip': ip_var.get(),
                    'netmask': netmask_var.get(),
                    'network': network_address,
                    'broadcast': broadcast_address,
                    'first_host': first_host,
                    'last_host': last_host,
                    'host_number': host_number_decimal_from_binary
                })
        except Exception as e:
            messagebox.showerror("错误", f"计算出错: {e}")

    row = 0
    ttk.Label(frame, text="IP地址 (十进制或二进制):").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=ip_var, width=30).grid(row=row, column=1, padx=5, pady=5)
    ttk.Entry(frame, textvariable=ip_converted_var, state="readonly", width=40).grid(row=row, column=2, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="子网掩码 (十进制或二进制):").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=netmask_var, width=30).grid(row=row, column=1, padx=5, pady=5)
    ttk.Entry(frame, textvariable=netmask_converted_var, state="readonly", width=40).grid(row=row, column=2, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="网络地址:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=network_info_var, state="readonly", width=30).grid(row=row, column=1, padx=5, pady=5)
    ttk.Entry(frame, textvariable=network_info_binary_var, state="readonly", width=40).grid(row=row, column=2, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="广播地址:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=broadcast_info_var, state="readonly", width=30).grid(row=row, column=1, padx=5, pady=5)
    ttk.Entry(frame, textvariable=broadcast_info_binary_var, state="readonly", width=40).grid(row=row, column=2, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="地址类别:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=network_class_var, state="readonly", width=30).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="第一个可用IP:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=first_available_ip_var, state="readonly", width=30).grid(row=row, column=1, padx=5, pady=5)
    ttk.Entry(frame, textvariable=first_available_ip_binary_var, state="readonly", width=40).grid(row=row, column=2, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="最后一个可用IP:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=last_available_ip_var, state="readonly", width=30).grid(row=row, column=1, padx=5, pady=5)
    ttk.Entry(frame, textvariable=last_available_ip_binary_var, state="readonly", width=40).grid(row=row, column=2, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="受限广播地址:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=restricted_broadcast_var, state="readonly", width=30).grid(row=row, column=1, padx=5, pady=5)
    ttk.Entry(frame, textvariable=restricted_broadcast_binary_var, state="readonly", width=40).grid(row=row, column=2, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="主机号:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=host_number_var, state="readonly", width=30).grid(row=row, column=1, padx=5, pady=5)
    ttk.Entry(frame, textvariable=host_number_binary_var, state="readonly", width=40).grid(row=row, column=2, padx=5, pady=5)
    row += 1
    ttk.Button(frame, text="计算", command=calculate_ip_info).grid(row=row, column=0, columnspan=3, pady=10)
    return frame
# ========== 内存单位转换器相关函数 ==========
def memory_converter_frame(parent, on_action=None):
    frame = ttk.Frame(parent)
    base_var = tk.IntVar(value=1024)
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    entries = {}
    def convert(from_unit):
        base = base_var.get()
        try:
            input_value = float(entries[from_unit].get())
        except ValueError:
            return
        unit_index = units.index(from_unit)
        bytes_value = input_value * (base ** unit_index)
        for unit in units:
            if unit == from_unit:
                continue
            exponent = units.index(unit)
            converted_value = bytes_value / (base ** exponent)
            entries[unit].delete(0, tk.END)
            entries[unit].insert(0, f"{converted_value:.6f}")
        if on_action:
            on_action({unit: entries[unit].get() for unit in units})
    frame_base = ttk.Frame(frame)
    frame_base.pack(pady=10)
    ttk.Radiobutton(frame_base, text="二进制 (1024)", variable=base_var, value=1024).pack(side=tk.LEFT, padx=5)
    ttk.Radiobutton(frame_base, text="十进制 (1000)", variable=base_var, value=1000).pack(side=tk.LEFT, padx=5)
    main_frame = ttk.Frame(frame)
    main_frame.pack(padx=10, pady=10)
    for row, unit in enumerate(units):
        ttk.Label(main_frame, text=unit, width=5).grid(row=row, column=0, padx=5)
        entry = ttk.Entry(main_frame, width=15)
        entry.grid(row=row, column=1, padx=5, pady=2)
        entries[unit] = entry
        ttk.Button(main_frame, text="转换", command=lambda u=unit: convert(u)).grid(row=row, column=2, padx=5)
    return frame

# ========== 二进制与十进制转换器相关函数 ==========
def bin_dec_converter_frame(parent, on_action=None):
    frame = ttk.Frame(parent)
    def convert():
        decimal_input = decimal_entry.get().strip()
        binary_input = binary_entry.get().strip()
        if decimal_input and binary_input:
            messagebox.showerror("错误", "请只输入1个数值")
            return
        elif decimal_input:
            try:
                decimal_num = int(decimal_input)
                binary_num = bin(decimal_num)[2:]
                result_label.config(text=f"十进制数 {decimal_num} 的二进制数是 {binary_num}")
                if on_action:
                    on_action({'decimal': decimal_num, 'binary': binary_num, 'type': 'dec2bin'})
            except ValueError:
                messagebox.showerror("错误", "输入的十进制数无效")
        elif binary_input:
            try:
                if len(binary_input) != 8 or not all(c in '01' for c in binary_input):
                    raise ValueError("输入的二进制数必须是8位")
                binary_num = binary_input
                decimal_num = int(binary_num, 2)
                result_label.config(text=f"二进制数 {binary_num} 的十进制数是 {decimal_num}")
                if on_action:
                    on_action({'decimal': decimal_num, 'binary': binary_num, 'type': 'bin2dec'})
            except ValueError as e:
                messagebox.showerror("错误", str(e))
        else:
            messagebox.showerror("错误", "请输入一个数值")

    def clear_inputs():
        decimal_entry.delete(0, tk.END)
        binary_entry.delete(0, tk.END)
        result_label.config(text="")
    title_label = ttk.Label(frame, text="二进制与十进制转换器", font=("Arial", 16, "bold"))
    title_label.pack(pady=10)
    decimal_frame = ttk.Frame(frame)
    decimal_frame.pack(pady=5)
    decimal_label = ttk.Label(decimal_frame, text="输入十进制数:", font=("Arial", 12))
    decimal_label.pack(side=tk.LEFT)
    decimal_entry = ttk.Entry(decimal_frame, width=20, font=("Arial", 12))
    decimal_entry.pack(side=tk.LEFT, padx=10)
    binary_frame = ttk.Frame(frame)
    binary_frame.pack(pady=5)
    binary_label = ttk.Label(binary_frame, text="输入二进制数:", font=("Arial", 12))
    binary_label.pack(side=tk.LEFT)
    binary_entry = ttk.Entry(binary_frame, width=20, font=("Arial", 12))
    binary_entry.pack(side=tk.LEFT, padx=10)
    button_frame = ttk.Frame(frame)
    button_frame.pack(pady=10)
    calculate_button = ttk.Button(button_frame, text="计算", command=convert)
    calculate_button.pack(side=tk.LEFT, padx=10)
    clear_button = ttk.Button(button_frame, text="清除输入", command=clear_inputs)
    clear_button.pack(side=tk.LEFT, padx=10)
    result_label = ttk.Label(frame, text="", font=("Arial", 12))
    result_label.pack(pady=10)
    frame.bind_all("<Return>", lambda event: convert())
    return frame

# ========== 停机时间与系统可用性相关函数 ==========
def downtime_availability_frame(parent, on_action=None):
    frame = ttk.Frame(parent)
    year_var = tk.StringVar()
    month_var = tk.StringVar()
    day_var = tk.StringVar()
    hour_var = tk.StringVar()
    minute_var = tk.StringVar()
    result_var = tk.StringVar()

    def calculate_availability():
        try:
            year = int(year_var.get()) if year_var.get() else 0
            month = int(month_var.get()) if month_var.get() else 0
            day = int(day_var.get()) if day_var.get() else 0
            hour = int(hour_var.get()) if hour_var.get() else 0
            minute = int(minute_var.get()) if minute_var.get() else 0

            total_minutes = (year * 365 * 24 * 60) + (month * 30 * 24 * 60) + (day * 24 * 60) + (hour * 60) + minute
            total_hours = total_minutes / 60

            if total_minutes <= 5:
                result = "系统可用性达到 99.999%"
            elif total_minutes <= 53:
                result = "系统可用性达到 99.99%"
            elif total_hours <= 8.8:
                result = "系统可用性达到 99.9%"
            else:
                result = "系统可用性低于 99.9%"

            result_var.set(result)
            if on_action:
                on_action({
                    'year': year,
                    'month': month,
                    'day': day,
                    'hour': hour,
                    'minute': minute,
                    'availability': result
                })
        except ValueError:
            messagebox.showerror("错误", "请输入有效的数字")

    def clear_inputs():
        year_var.set("")
        month_var.set("")
        day_var.set("")
        hour_var.set("")
        minute_var.set("")
        result_var.set("")

    row = 0
    ttk.Label(frame, text="年:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=year_var, width=10).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="月:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=month_var, width=10).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="日:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=day_var, width=10).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="小时:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=hour_var, width=10).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="分钟:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=minute_var, width=10).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="结果:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=result_var, state="readonly", width=30).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    button_frame = ttk.Frame(frame)
    button_frame.grid(row=row, column=0, columnspan=2, pady=10)
    ttk.Button(button_frame, text="判断", command=calculate_availability).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="清除输入", command=clear_inputs).pack(side=tk.LEFT, padx=5)
    return frame

# ========== ITU标准数据传输速度相关函数 ==========
def itu_speed_calculator_frame(parent, on_action=None):
    frame = ttk.Frame(parent)
    oc_x_var = tk.StringVar()
    result_var = tk.StringVar()

    def calculate_speed():
        try:
            oc_x = int(oc_x_var.get())
            speed = oc_x * 51.84
            result_var.set(f"{speed} Mbps")
            if on_action:
                on_action({'oc_x': oc_x, 'speed': speed})
        except ValueError:
            messagebox.showerror("错误", "请输入有效的整数")

    def clear_inputs():
        oc_x_var.set("")
        result_var.set("")

    row = 0
    ttk.Label(frame, text="输入OC - X中的X值:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=oc_x_var, width=10).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="数据传输速度:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=result_var, state="readonly", width=20).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    button_frame = ttk.Frame(frame)
    button_frame.grid(row=row, column=0, columnspan=2, pady=10)
    ttk.Button(button_frame, text="计算", command=calculate_speed).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="清除输入", command=clear_inputs).pack(side=tk.LEFT, padx=5)
    return frame

# ========== IPv6地址判断相关函数 ==========
def ipv6_validator_frame(parent, on_action=None):
    frame = ttk.Frame(parent)
    ipv6_var = tk.StringVar()
    is_valid_var = tk.StringVar()
    reason_var = tk.StringVar()

    def validate_ipv6():
        address = ipv6_var.get().strip()
        try:
            # 尝试解析IPv6地址
            ip = ipaddress.IPv6Address(address)
            is_valid_var.set("是")
            reason_var.set("输入的是有效的IPv6地址")
            if on_action:
                on_action({'address': address, 'is_valid': True, 'reason': '有效的IPv6地址'})
        except ValueError as e:
            is_valid_var.set("否")
            reason_var.set(str(e))
            if on_action:
                on_action({'address': address, 'is_valid': False, 'reason': str(e)})

    def clear_inputs():
        ipv6_var.set("")
        is_valid_var.set("")
        reason_var.set("")

    row = 0
    ttk.Label(frame, text="输入IPv6地址:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=ipv6_var, width=40).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    ttk.Label(frame, text="是否有效:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=is_valid_var, state="readonly", width=10).grid(row=row, column=1, padx=5, pady=5, sticky='w')
    row += 1
    ttk.Label(frame, text="判断理由:").grid(row=row, column=0, padx=10, pady=5, sticky='ne')
    reason_entry = tk.Text(frame, height=4, width=40, state="disabled", wrap="word")
    reason_entry.grid(row=row, column=1, padx=5, pady=5, sticky='w')

    # 更新reason_var时同步更新Text内容
    def update_reason_entry(*args):
        reason_entry.config(state="normal")
        reason_entry.delete("1.0", tk.END)
        reason_entry.insert(tk.END, reason_var.get())
        reason_entry.config(state="disabled")
    reason_var.trace_add("write", update_reason_entry)
    row += 1
    button_frame = ttk.Frame(frame)
    button_frame.grid(row=row, column=0, columnspan=2, pady=10)
    ttk.Button(button_frame, text="判断", command=validate_ipv6).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="清除输入", command=clear_inputs).pack(side=tk.LEFT, padx=5)
    return frame

# ========== 交换机全双工带宽计算相关函数 ==========
def switch_bandwidth_calculator_frame(parent, on_action=None):
    frame = ttk.Frame(parent)
    
    # 创建变量存储输入和输出
    port100_count_var = tk.StringVar()
    port1000_count_var = tk.StringVar()
    port10000_count_var = tk.StringVar()
    total_bandwidth_var = tk.StringVar()
    
    def calculate_bandwidth():
        try:
            # 获取输入值并转换为整数
            port100_count = int(port100_count_var.get() or "0")
            port1000_count = int(port1000_count_var.get() or "0")
            port10000_count = int(port10000_count_var.get() or "0")
            
            # 计算总带宽（Mbps）
            total_mbps = (port100_count * 100 + port1000_count * 1000 + port10000_count * 10000) * 2
            
            # 转换为合适的单位（Gbps）
            if total_mbps >= 1000:
                total_gbps = total_mbps / 1000
                result_text = f"{total_gbps:.2f} Gbps"
            else:
                result_text = f"{total_mbps} Mbps"
            
            total_bandwidth_var.set(result_text)
            
            # 保存历史记录
            if on_action:
                on_action({
                    '100Mbps端口数': port100_count,
                    '1000Mbps端口数': port1000_count,
                    '10000Mbps端口数': port10000_count,
                    '总带宽': result_text
                })
                
        except ValueError:
            messagebox.showerror("错误", "请输入有效的整数")
    
    def clear_inputs():
        port100_count_var.set("")
        port1000_count_var.set("")
        port10000_count_var.set("")
        total_bandwidth_var.set("")
    
    # 创建界面元素
    row = 0
    ttk.Label(frame, text="100Mbps端口数量:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=port100_count_var, width=10).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    
    ttk.Label(frame, text="1000Mbps端口数量:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=port1000_count_var, width=10).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    
    ttk.Label(frame, text="10000Mbps端口数量:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=port10000_count_var, width=10).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    
    ttk.Label(frame, text="全双工总带宽:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=total_bandwidth_var, state="readonly", width=20).grid(row=row, column=1, padx=5, pady=5, sticky='w')
    row += 1
    
    button_frame = ttk.Frame(frame)
    button_frame.grid(row=row, column=0, columnspan=2, pady=10)
    ttk.Button(button_frame, text="计算", command=calculate_bandwidth).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="清除输入", command=clear_inputs).pack(side=tk.LEFT, padx=5)
    
    return frame

# ========== 子网划分相关函数 ==========
def subnet_calculator_frame(parent, on_action=None):
    frame = ttk.Frame(parent)
    
    # 创建变量存储输入和输出
    ip_var = tk.StringVar()
    cidr_var = tk.StringVar()
    subnet_count_var = tk.StringVar()
    hosts_var = tk.StringVar()
    sort_order_var = tk.StringVar(value="从大到小")
    result_var = tk.StringVar()
    
    def calculate_subnets():
        try:
            # 1. 基础输入解析
            ip = ip_var.get().strip()
            cidr = int(cidr_var.get())
            subnet_count = int(subnet_count_var.get())
            hosts_input = hosts_var.get().strip()
            sort_order = sort_order_var.get()
            
            # 2. 校验：主机数列表
            hosts_list = [int(h.strip()) for h in hosts_input.split(',') if h.strip()]
            if len(hosts_list) != subnet_count:
                messagebox.showerror("错误", f"主机数数量（{len(hosts_list)}）与子网个数（{subnet_count}）不匹配！")
                return
            
            # 3. 校验：IP + CIDR 合法性
            try:
                # 强制严格模式，确保 IP 在网络地址范围内
                network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=True) 
            except ValueError as e:
                messagebox.showerror("错误", f"IP/CIDR 不合法！需满足：\n- IP 是网络地址（如 192.168.1.0 而非 192.168.1.5）\n- CIDR 格式正确\n错误详情：{str(e)}")
                return
            
            # 4. 排序主机数（按需调整）
            if sort_order == "从大到小":
                hosts_list.sort(reverse=True)
            else:
                hosts_list.sort()
            
            current_network = network
            subnets = []
            
            for idx, required_hosts in enumerate(hosts_list, 1):
                # 5. 计算所需主机位 + 子网前缀
                # 需容纳的主机数 = required_hosts ，所以总地址数至少是 required_hosts + 2（网络+广播）
                total_addresses = required_hosts + 2  
                if total_addresses <= 0:
                    messagebox.showerror("错误", f"第 {idx} 个子网主机数不能为负数！")
                    return
                
                # 计算需要的主机位数（向上取整）
                host_bits = total_addresses.bit_length()  
                # 若 host_bits 刚好是 total_addresses 的位数（如 57 是 6 位），但 2^host_bits < total_addresses ，则需要 +1
                if (1 << host_bits) < total_addresses:
                    host_bits += 1
                
                subnet_cidr = 32 - host_bits
                
                # 6. 关键校验：新前缀必须大于原 CIDR
                if subnet_cidr <= cidr:
                    messagebox.showerror("错误", f"第 {idx} 个子网需要 {required_hosts} 台主机，但计算出的子网前缀 {subnet_cidr} ≤ 原前缀 {cidr} ，无法划分！")
                    return
                
                # 7. 划分子网（捕获边界错误）
                try:
                    subnet = next(current_network.subnets(new_prefix=subnet_cidr))
                except StopIteration:
                    messagebox.showerror("错误", f"第 {idx} 个子网划分失败，剩余网络空间不足！")
                    return
                
                # 8. 计算可用 IP 范围
                hosts = list(subnet.hosts())
                if not hosts:
                    messagebox.showerror("错误", f"第 {idx} 个子网无可用主机地址！")
                    return
                
                # 9. 保存子网信息
                subnets.append({
                    'network': str(subnet.network_address),
                    'prefix': subnet.prefixlen,
                    'netmask': str(subnet.netmask),
                    'first_ip': str(hosts[0]),
                    'last_ip': str(hosts[-1]),
                    'broadcast': str(subnet.broadcast_address),
                    'hosts': required_hosts
                })
                
                # 10. 更新剩余网络（取第一个剩余网段）
                remaining = list(current_network.address_exclude(subnet))
                if not remaining:
                    break  # 无剩余网段，结束划分
                current_network = remaining[0]
            
            # 11. 输出结果
            result_text = "子网划分结果：\n\n"
            for i, subnet in enumerate(subnets):
                result_text += f"子网 {i+1}（需容纳 {subnet['hosts']} 台主机）：\n"
                result_text += f"  网络地址：{subnet['network']}/{subnet['prefix']}\n"
                result_text += f"  子网掩码：{subnet['netmask']}\n"
                result_text += f"  可用 IP 范围：{subnet['first_ip']} - {subnet['last_ip']}\n"
                result_text += f"  广播地址：{subnet['broadcast']}\n\n"
            
            result_var.set(result_text)
            
            # 保存历史（按需启用）
            if on_action:
                on_action({
                    'ip': ip,
                    'cidr': cidr,
                    'subnet_count': subnet_count,
                    'hosts_list': hosts_list,
                    'sort_order': sort_order,
                    'subnets': subnets
                })
                
        except ValueError as e:
            messagebox.showerror("错误", f"输入格式错误：{str(e)}")
        except Exception as e:
            messagebox.showerror("错误", f"计算出错：{str(e)}")
    
    # 以下是界面元素（保持原有，可按需美化）
    def clear_inputs():
        ip_var.set("")
        cidr_var.set("")
        subnet_count_var.set("")
        hosts_var.set("")
        result_var.set("")
    
    row = 0
    ttk.Label(frame, text="IP地址:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=ip_var, width=20).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    
    ttk.Label(frame, text="子网掩码(/格式):").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=cidr_var, width=5).grid(row=row, column=1, padx=5, pady=5, sticky='w')
    row += 1
    
    ttk.Label(frame, text="子网个数:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=subnet_count_var, width=5).grid(row=row, column=1, padx=5, pady=5, sticky='w')
    row += 1
    
    ttk.Label(frame, text="各子网主机数(逗号分隔):").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ttk.Entry(frame, textvariable=hosts_var, width=30).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    
    ttk.Label(frame, text="排序方式:").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    sort_frame = ttk.Frame(frame)
    sort_frame.grid(row=row, column=1, padx=5, pady=5, sticky='w')
    ttk.Radiobutton(sort_frame, text="从大到小", variable=sort_order_var, value="从大到小").pack(side=tk.LEFT)
    ttk.Radiobutton(sort_frame, text="从小到大", variable=sort_order_var, value="从小到大").pack(side=tk.LEFT)
    row += 1
    
    ttk.Label(frame, text="结果:").grid(row=row, column=0, padx=10, pady=5, sticky='ne')
    result_text = tk.Text(frame, height=10, width=60)
    result_text.grid(row=row, column=1, padx=5, pady=5, sticky='w')
    scrollbar = ttk.Scrollbar(frame, command=result_text.yview)
    scrollbar.grid(row=row, column=2, sticky='ns')
    result_text.config(yscrollcommand=scrollbar.set)
    
    def update_result_text(*args):
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result_var.get())
    result_var.trace_add("write", update_result_text)
    row += 1
    
    button_frame = ttk.Frame(frame)
    button_frame.grid(row=row, column=0, columnspan=2, pady=10)
    ttk.Button(button_frame, text="计算", command=calculate_subnets).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="清除输入", command=clear_inputs).pack(side=tk.LEFT, padx=5)
    
    return frame

# ========== IP地址聚合相关函数 ==========
def ip_aggregation_frame(parent, on_action=None):
    frame = ttk.Frame(parent)
    
    # 创建变量存储输入和输出
    ip_input = tk.Text(frame, height=10, width=40)
    result_var = tk.StringVar()
    
    def aggregate_ips():
        try:
            # 获取输入的IP地址列表
            ip_text = ip_input.get(1.0, tk.END).strip()
            ip_lines = [line.strip() for line in ip_text.split('\n') if line.strip()]
            
            # 解析IP地址和CIDR前缀
            networks = []
            for line in ip_lines:
                try:
                    # 尝试解析为带CIDR的网络
                    network = ipaddress.IPv4Network(line, strict=False)
                    networks.append(network)
                except ValueError:
                    try:
                        # 尝试解析为不带CIDR的IP（默认为/32）
                        ip = ipaddress.IPv4Address(line)
                        network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
                        networks.append(network)
                    except ValueError:
                        messagebox.showerror("错误", f"无效的IP地址或网络: {line}")
                        return
            
            if len(networks) < 2:
                messagebox.showerror("错误", "请至少输入两个IP地址或网络")
                return
            
            # 按网络地址排序
            networks.sort(key=lambda net: net.network_address)
            
            # 实现IP地址聚合逻辑
            def aggregate_networks(networks):
                # 复制并排序网络列表
                sorted_nets = sorted(networks, key=lambda n: (n.network_address, n.prefixlen))
                result = []
                
                for net in sorted_nets:
                    # 如果结果列表为空，直接添加当前网络
                    if not result:
                        result.append(net)
                        continue
                    
                    merged = False
                    # 尝试与结果列表中的最后一个网络合并
                    while len(result) > 0:
                        last_net = result[-1]
                        # 检查是否可以合并
                        if last_net.supernet().overlaps(net) and last_net.supernet().prefixlen < 32:
                            # 创建父网络
                            parent_net = last_net.supernet()
                            # 检查父网络是否包含当前网络且不包含其他网络
                            if net.subnet_of(parent_net):
                                # 移除最后一个网络
                                result.pop()
                                # 添加所有包含在父网络中的网络
                                temp = [parent_net]
                                for n in result:
                                    if n.subnet_of(parent_net):
                                        temp.append(n)
                                # 从结果中移除所有被包含的网络
                                for n in temp[1:]:
                                    if n in result:
                                        result.remove(n)
                                # 添加父网络
                                result.append(parent_net)
                                merged = True
                                break
                            else:
                                break
                        else:
                            break
                    
                    # 如果无法合并，直接添加当前网络
                    if not merged:
                        result.append(net)
                
                # 再次检查是否可以合并结果中的网络
                optimized = False
                while not optimized:
                    optimized = True
                    for i in range(len(result)):
                        for j in range(i + 1, len(result)):
                            # 检查两个网络是否可以合并
                            if result[i].supernet().overlaps(result[j]) and result[i].supernet().prefixlen < 32:
                                parent_net = result[i].supernet()
                                if result[j].subnet_of(parent_net):
                                    # 移除两个网络，添加父网络
                                    result.pop(j)
                                    result.pop(i)
                                    result.append(parent_net)
                                    optimized = False
                                    break
                        if not optimized:
                            break
                
                return result
            
            # 执行聚合
            aggregated_networks = aggregate_networks(networks)
            
            # 计算聚合后所有可用IP地址数
            total_usable_ips = 0
            for net in aggregated_networks:
                if net.prefixlen < 31:
                    total_usable_ips += net.num_addresses - 2
                else:
                    total_usable_ips += 0

            # 生成结果文本
            result_text = "聚合后的IP地址范围:\n\n"
            for i, net in enumerate(aggregated_networks, 1):
                result_text += f"{i}. {net}\n"
                result_text += f"   网络地址: {net.network_address}\n"
                result_text += f"   广播地址: {net.broadcast_address}\n"
                result_text += f"   子网掩码: {net.netmask}\n"
                result_text += f"   可用IP数量: {net.num_addresses - 2 if net.prefixlen < 31 else 0}\n"
                if net.prefixlen < 31:
                    result_text += f"   可用IP范围: {list(net.hosts())[0]} - {list(net.hosts())[-1]}\n"
                result_text += "\n"
            result_text += f"聚合后所有可用IP地址总数: {total_usable_ips}\n"
            
            result_var.set(result_text)
            
            # 保存历史记录
            if on_action:
                on_action({
                    'input_networks': [str(net) for net in networks],
                    'aggregated_networks': [str(net) for net in aggregated_networks],
                    'total_usable_ips': total_usable_ips
                })
                
        except ValueError as e:
            messagebox.showerror("错误", f"输入格式错误: {str(e)}")
        except Exception as e:
            messagebox.showerror("错误", f"计算过程中出错: {str(e)}")
    
    def clear_inputs():
        ip_input.delete(1.0, tk.END)
        result_var.set("")
    
    # 创建界面元素（保持不变）
    row = 0
    ttk.Label(frame, text="输入IP地址或网络(每行一个):").grid(row=row, column=0, padx=10, pady=5, sticky='e')
    ip_input.grid(row=row, column=1, padx=5, pady=5)
    scrollbar = ttk.Scrollbar(frame, command=ip_input.yview)
    scrollbar.grid(row=row, column=2, sticky='ns')
    ip_input.config(yscrollcommand=scrollbar.set)
    row += 1
    
    ttk.Label(frame, text="聚合结果:").grid(row=row, column=0, padx=10, pady=5, sticky='ne')
    result_text = tk.Text(frame, height=10, width=40)
    result_text.grid(row=row, column=1, padx=5, pady=5, sticky='w')
    scrollbar = ttk.Scrollbar(frame, command=result_text.yview)
    scrollbar.grid(row=row, column=2, sticky='ns')
    result_text.config(yscrollcommand=scrollbar.set)
    
    # 绑定结果变量到文本框
    def update_result_text(*args):
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result_var.get())
    result_var.trace_add("write", update_result_text)
    row += 1
    
    button_frame = ttk.Frame(frame)
    button_frame.grid(row=row, column=0, columnspan=2, pady=10)
    ttk.Button(button_frame, text="聚合", command=aggregate_ips).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="清除输入", command=clear_inputs).pack(side=tk.LEFT, padx=5)
    
    return frame

# ========== RIP 路由表更新计算功能 ==========
def rip_route_update_frame(parent, on_action=None):
    frame = ttk.Frame(parent)

    # R1初始路由表（①②③为待计算的原始距离，界面仅展示）
    r1_initial_display = [
        {"network": "10.0.0.0", "distance": "0", "next_hop": "直接"},
        {"network": "20.0.0.0", "distance": "①", "next_hop": "R2"},
        {"network": "30.0.0.0", "distance": "②", "next_hop": "R3"},
        {"network": "40.0.0.0", "distance": "③", "next_hop": "R4"},
    ]

    # R2发送的[V,D]报文（用户输入）
    r2_vd_vars = [
        {"network": "10.0.0.0", "distance_var": tk.StringVar(value="2")},
        {"network": "20.0.0.0", "distance_var": tk.StringVar(value="3")},
        {"network": "30.0.0.0", "distance_var": tk.StringVar(value="4")},
        {"network": "40.0.0.0", "distance_var": tk.StringVar(value="4")},
    ]

    # R1更新后的路由表（用户只需输入距离）
    r1_updated_vars = [
        {"network": "10.0.0.0", "distance_var": tk.StringVar(value="0")},
        {"network": "20.0.0.0", "distance_var": tk.StringVar(value="")},
        {"network": "30.0.0.0", "distance_var": tk.StringVar(value="")},
        {"network": "40.0.0.0", "distance_var": tk.StringVar(value="")},
    ]

    result_var = tk.StringVar()

    def calculate_rip_update():
        try:
            # 解析输入数据
            r2_distances = [int(vd["distance_var"].get()) for vd in r2_vd_vars]
            r1_updated_distances = [int(route["distance_var"].get()) for route in r1_updated_vars]
            
            # 验证10.0.0.0条目有效性
            if r1_updated_distances[0] != 0:
                messagebox.showerror("错误", "10.0.0.0条目更新后必须是距离0")
                return
                
            ranges = []
            # 计算①②③的可能取值范围
            for i in range(1, 4):
                network = r1_initial_display[i]["network"]
                r2_distance = r2_distances[i]
                r2_plus_1 = r2_distance + 1
                updated_distance = r1_updated_distances[i]
                
                if updated_distance == r2_plus_1:
                    # 关键修改：当更新后距离等于R2+1时，原始距离应≥R2+1
                    ranges.append(f"≥{r2_plus_1}")
                elif updated_distance < r2_plus_1:
                    # 原始距离 = 更新后距离（因为原始距离 < R2+1时选择原始距离）
                    ranges.append(f"={updated_distance}")
                else:
                    ranges.append("不可能（更新后的距离 > R2+1）")
            
            # 生成结果文本
            result_text = (
                "计算结果：\n"
                f"①（20.0.0.0原始距离）取值范围：{ranges[0]}\n"
                f"②（30.0.0.0原始距离）取值范围：{ranges[1]}\n"
                f"③（40.0.0.0原始距离）取值范围：{ranges[2]}\n"
            )
            result_var.set(result_text)
        
            
                # 保存历史记录
            if on_action:
                on_action({
                        "r2_vd": [{"network": vd["network"], "distance": vd["distance_var"].get()} for vd in r2_vd_vars],
                        "r1_updated": [
                            {"network": route["network"], "distance": route["distance_var"].get()}
                            for route in r1_updated_vars
                        ],
                        "ranges": ranges
                })
                    
        except ValueError as e:
                messagebox.showerror("错误", f"输入格式错误：{str(e)}")
        except Exception as e:
                messagebox.showerror("错误", f"计算过程出错：{str(e)}")

    def clear_inputs():
        for vd in r2_vd_vars:
            vd["distance_var"].set("")
        for route in r1_updated_vars:
            if route["network"] != "10.0.0.0":
                route["distance_var"].set("")
        result_var.set("")

    # 界面布局（移除下一跳输入列）
    row = 0
    ttk.Label(frame, text="R1初始路由表:", font=("Arial", 10, "bold")).grid(row=row, column=0, columnspan=2, pady=5, sticky="w")
    row += 1
    
    ttk.Label(frame, text="目的网络", width=15).grid(row=row, column=0, padx=2, pady=2)
    ttk.Label(frame, text="距离", width=10).grid(row=row, column=1, padx=2, pady=2)
    row += 1
    
    for route in r1_initial_display:
        ttk.Label(frame, text=route["network"], width=15).grid(row=row, column=0, padx=2, pady=2)
        ttk.Label(frame, text=route["distance"], width=10).grid(row=row, column=1, padx=2, pady=2)
        row += 1
    
    ttk.Label(frame, text="R2发送的[V,D]报文:", font=("Arial", 10, "bold")).grid(row=row, column=0, columnspan=2, pady=5, sticky="w")
    row += 1
    
    ttk.Label(frame, text="目的网络", width=15).grid(row=row, column=0, padx=2, pady=2)
    ttk.Label(frame, text="距离", width=10).grid(row=row, column=1, padx=2, pady=2)
    row += 1
    
    for vd in r2_vd_vars:
        ttk.Label(frame, text=vd["network"], width=15).grid(row=row, column=0, padx=2, pady=2)
        ttk.Entry(frame, textvariable=vd["distance_var"], width=10).grid(row=row, column=1, padx=2, pady=2)
        row += 1
    
    ttk.Label(frame, text="当R1收到R2发送的[V,D]报文后R1更新后的路由表:", font=("Arial", 10, "bold")).grid(row=row, column=0, columnspan=2, pady=5, sticky="w")
    row += 1
    
    ttk.Label(frame, text="目的网络", width=15).grid(row=row, column=0, padx=2, pady=2)
    ttk.Label(frame, text="距离", width=10).grid(row=row, column=1, padx=2, pady=2)
    row += 1
    
    for route in r1_updated_vars:
        ttk.Label(frame, text=route["network"], width=15).grid(row=row, column=0, padx=2, pady=2)
        ttk.Entry(frame, textvariable=route["distance_var"], width=10).grid(row=row, column=1, padx=2, pady=2)
        row += 1
    
    # 右侧结果区
    result_frame = ttk.Frame(frame)
    result_frame.grid(row=0, column=2, rowspan=row, padx=20, pady=5, sticky="nsw")
    ttk.Label(result_frame, text="计算结果:", font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 5))
    ttk.Label(result_frame, textvariable=result_var, wraplength=300, justify="left").pack(anchor="w", pady=(0, 10))
    button_frame = ttk.Frame(result_frame)
    button_frame.pack(anchor="w", pady=10)
    ttk.Button(button_frame, text="计算", command=calculate_rip_update).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="清除", command=clear_inputs).pack(side=tk.LEFT, padx=5)
    
    return frame






# ========== 主程序 ==========
import json
import os

class NCREApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("简易的网络技术计算器软件")
        # 设置窗口大小和最小最大尺寸
        self.geometry("1100x500")  # (width)，(height)
        # self.minsize(400, 500)
        # self.maxsize(1600, 1200)
        self.style = ttk.Style()
        self.style.theme_use('clam')
        # 历史记录文件
        self.history_file = os.path.join(os.path.dirname(__file__), 'ncre_history.json')
        self.history = self.load_history()
        # 主布局
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        # 侧边栏
        sidebar = ttk.Frame(self, width=180)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)
        # 内容区
        self.content_frame = ttk.Frame(self)
        self.content_frame.grid(row=0, column=1, sticky="nsew")
        self.content_frame.grid_propagate(True)
        # 历史记录按钮
        ttk.Button(sidebar, text="历史记录", command=self.show_history).pack(fill=tk.X, pady=(10, 20), padx=10)
        # 菜单按钮
        self.frames = {}
        self.menu_items = [
            ("IP地址计算器", self.ip_calculator_frame_with_history),
            ("内存单位转换器", self.memory_converter_frame_with_history),
            ("二/十进制转换器", self.bin_dec_converter_frame_with_history),
            ("停机时间与系统可用性", self.downtime_availability_frame_with_history),
            ("ITU标准数据传输速度", self.itu_speed_calculator_frame_with_history),
            ("IPv6地址判断", self.ipv6_validator_frame_with_history),
            ("交换机全双工带宽计算", self.switch_bandwidth_calculator_frame_with_history),
            ("子网划分", self.subnet_calculator_frame_with_history),
            ("IP地址聚合", self.ip_aggregation_frame_with_history), 
            ("RIP 路由表更新", self.rip_route_update_frame_with_history)




        ]
        for idx, (name, frame_func) in enumerate(self.menu_items):
            btn = ttk.Button(sidebar, text=name, command=lambda f=frame_func: self.show_frame(f))
            btn.pack(fill=tk.X, pady=5, padx=10)
        # 默认显示第一个
        self.show_frame(self.menu_items[0][1])

    def show_frame(self, frame_func):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        frame = frame_func(self.content_frame)
        frame.pack(fill=tk.BOTH, expand=True)

    def show_history(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        frame = ttk.Frame(self.content_frame)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="历史记录", font=("Arial", 16, "bold")).pack(pady=10)
        text = tk.Text(frame, wrap=tk.WORD, height=30)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        if not self.history:
            text.insert(tk.END, "暂无历史记录。")
        else:
            for item in reversed(self.history):
                text.insert(tk.END, json.dumps(item, ensure_ascii=False, indent=2) + '\n' + '-'*40 + '\n')
        text.config(state=tk.DISABLED)

    def save_history(self):
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            messagebox.showerror("保存历史失败", str(e))

    def load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def itu_speed_calculator_frame_with_history(self, parent):
        def save_itu_history(data):
            self.history.append({'type': 'ITU标准数据传输速度计算', **data})
            self.save_history()
        return itu_speed_calculator_frame(parent, on_action=save_itu_history)
    
    # ========== 带历史的功能区包装 ==========
    def ip_calculator_frame_with_history(self, parent):
        def save_ip_history(data):
            self.history.append({'type': 'IP地址计算', **data})
            self.save_history()
        return ip_calculator_frame(parent, on_action=save_ip_history)

    def memory_converter_frame_with_history(self, parent):
        def save_mem_history(data):
            self.history.append({'type': '内存单位转换', 'values': data})
            self.save_history()
        return memory_converter_frame(parent, on_action=save_mem_history)

    def bin_dec_converter_frame_with_history(self, parent):
        def save_bin_history(data):
            self.history.append({'type': '二/十进制转换', **data})
            self.save_history()
        return bin_dec_converter_frame(parent, on_action=save_bin_history)

    def downtime_availability_frame_with_history(self, parent):
        def save_downtime_history(data):
            self.history.append({'type': '停机时间与系统可用性', **data})
            self.save_history()
        return downtime_availability_frame(parent, on_action=save_downtime_history)

    def ipv6_validator_frame_with_history(self, parent):
        def save_ipv6_history(data):
            self.history.append({'type': 'IPv6地址判断', **data})
            self.save_history()
        return ipv6_validator_frame(parent, on_action=save_ipv6_history)

    def switch_bandwidth_calculator_frame_with_history(self, parent):
        def save_switch_history(data):
            self.history.append({'type': '交换机全双工带宽计算', **data})
            self.save_history()
        return switch_bandwidth_calculator_frame(parent, on_action=save_switch_history)

    def subnet_calculator_frame_with_history(self, parent):
        def save_subnet_history(data):
            self.history.append({'type': '子网划分', **data})
            self.save_history()
        return subnet_calculator_frame(parent, on_action=save_subnet_history)
    
    def ip_aggregation_frame_with_history(self, parent):
        def save_aggregation_history(data):
            self.history.append({'type': 'IP地址聚合', **data})
            self.save_history()
        return ip_aggregation_frame(parent, on_action=save_aggregation_history)

    def rip_route_update_frame_with_history(self, parent):
        def save_rip_history(data):
            self.history.append({'type': 'RIP 路由更新', **data})
            self.save_history()
        return rip_route_update_frame(parent, on_action=save_rip_history)






if __name__ == "__main__":
    app = NCREApp()
    app.mainloop()
