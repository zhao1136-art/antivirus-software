"""
安盾 引擎更新报告 - 飞书幻灯片生成脚本
通过 lark-cli 创建 7 页幻灯片
"""
import subprocess
import sys
import json
import os

PRESENTATION_ID = "M21NsZdfLlNz4kdrLmncvEmanTf"

# 使用 lark-cli 独立 exe 路径，避免 PowerShell 执行策略问题
LARK_CLI_EXE = r"c:\Users\Administrator\.trae-cn\plugins\trae-remote-official\lark\1.0.3\bin\lark-cli.exe"

def run_lark(*args):
    """运行 lark-cli 命令"""
    cmd = [LARK_CLI_EXE] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout.strip(), result.stderr.strip(), result.returncode

# ══════════════════════════════════════════════════════════════
#  Slide 1: 封面
# ══════════════════════════════════════════════════════════════
SLIDE1 = '''<slide xmlns="http://www.larkoffice.com/sml/2.0">
<style><fill><fillColor color="#0a0e1a"/></fill></style>
<data>
  <shape type="rect" topLeftX="0" topLeftY="0" width="960" height="540">
    <fill><fillColor color="linear-gradient(135deg,rgba(10,14,26,1) 0%,rgba(20,30,60,1) 100%)"/></fill>
  </shape>
  <shape type="rect" topLeftX="60" topLeftY="0" width="4" height="540">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="160" width="800" height="140">
    <content textType="title" textAlign="left" fontSize="48" fontFamily="Microsoft YaHei" color="#f4f4f9" bold="true">
      <p>安盾 <span color="#00d9c0">引擎更新报告</span></p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="310" width="700" height="50">
    <content textType="sub-headline" textAlign="left" fontSize="22" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>Logo 启动画面 + 引擎并行加载 + 持久化存储</p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="390" width="400" height="30">
    <content textType="body" textAlign="left" fontSize="14" fontFamily="Microsoft YaHei" color="#5c5c75">
      <p>版本 1.0.2 · 2026年8月</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="440" width="200" height="3">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
</data>
</slide>'''

# ══════════════════════════════════════════════════════════════
#  Slide 2: 更新亮点
# ══════════════════════════════════════════════════════════════
SLIDE2 = '''<slide xmlns="http://www.larkoffice.com/sml/2.0">
<style><fill><fillColor color="#0a0e1a"/></fill></style>
<data>
  <shape type="rect" topLeftX="60" topLeftY="0" width="4" height="540">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="36" width="800" height="50">
    <content textType="title" textAlign="left" fontSize="36" fontFamily="Microsoft YaHei" color="#f4f4f9" bold="true">
      <p>本次更新亮点</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="90" width="60" height="3">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="130" width="240" height="160" cornerRadius="12">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="150" width="200" height="30">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>启动动画</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="190" width="200" height="40">
    <content textType="headline" textAlign="left" fontSize="42" fontFamily="Microsoft YaHei" color="#00d9c0" bold="true">
      <p>600ms</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="235" width="200" height="30">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#5c5c75">
      <p>淡入渐变动画</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="370" topLeftY="130" width="240" height="160" cornerRadius="12">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="390" topLeftY="150" width="200" height="30">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>引擎并行加载</p>
    </content>
  </shape>
  <shape type="text" topLeftX="390" topLeftY="190" width="200" height="40">
    <content textType="headline" textAlign="left" fontSize="42" fontFamily="Microsoft YaHei" color="#00d9c0" bold="true">
      <p>6 模块</p>
    </content>
  </shape>
  <shape type="text" topLeftX="390" topLeftY="235" width="200" height="30">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#5c5c75">
      <p>同步异步加载</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="640" topLeftY="130" width="240" height="160" cornerRadius="12">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="660" topLeftY="150" width="200" height="30">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>持久化存储</p>
    </content>
  </shape>
  <shape type="text" topLeftX="660" topLeftY="190" width="200" height="40">
    <content textType="headline" textAlign="left" fontSize="42" fontFamily="Microsoft YaHei" color="#00d9c0" bold="true">
      <p>3 文件</p>
    </content>
  </shape>
  <shape type="text" topLeftX="660" topLeftY="235" width="200" height="30">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#5c5c75">
      <p>配置/天数/缓存</p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="330" width="800" height="70">
    <content textType="body" textAlign="left" fontSize="15" fontFamily="Microsoft YaHei" color="#c6c6c6" lineSpacing="1.8">
      <p>程序启动时即时弹出 Logo 窗口执行淡入动画，同时后台线程并行加载全套引擎资源</p>
      <p>推出统一退出流程：保存状态 → Logo 淡出 → 资源释放 → 进程退出</p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="430" width="800" height="40">
    <content textType="body" textAlign="left" fontSize="14" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p><span bold="true" color="#00d9c0">新增文件:</span> logo_splash.py / engine_loader.py / 持久化模块增强</p>
    </content>
  </shape>
</data>
</slide>'''

# ══════════════════════════════════════════════════════════════
#  Slide 3: Logo 启动画面详解
# ══════════════════════════════════════════════════════════════
SLIDE3 = '''<slide xmlns="http://www.larkoffice.com/sml/2.0">
<style><fill><fillColor color="#0a0e1a"/></fill></style>
<data>
  <shape type="rect" topLeftX="60" topLeftY="0" width="4" height="540">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="36" width="500" height="50">
    <content textType="title" textAlign="left" fontSize="36" fontFamily="Microsoft YaHei" color="#f4f4f9" bold="true">
      <p>Logo 启动画面详解</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="90" width="60" height="3">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="120" width="500" height="30">
    <content textType="body" textAlign="left" fontSize="15" fontFamily="Microsoft YaHei" color="#c6c6c6">
      <p><span color="#00d9c0" bold="true">1.</span> Logo 窗口弹出，执行 600ms 淡入动画</p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="160" width="500" height="30">
    <content textType="body" textAlign="left" fontSize="15" fontFamily="Microsoft YaHei" color="#c6c6c6">
      <p><span color="#00d9c0" bold="true">2.</span> 后台线程并行加载 6 大引擎资源</p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="200" width="500" height="30">
    <content textType="body" textAlign="left" fontSize="15" fontFamily="Microsoft YaHei" color="#c6c6c6">
      <p><span color="#00d9c0" bold="true">3.</span> 等待规则：引擎先完等动画，动画先完等引擎</p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="240" width="500" height="30">
    <content textType="body" textAlign="left" fontSize="15" fontFamily="Microsoft YaHei" color="#c6c6c6">
      <p><span color="#00d9c0" bold="true">4.</span> Logo 淡出 → 主窗口（安盾安全中心）显示</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="290" width="500" height="200" cornerRadius="8">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="300" width="460" height="20">
    <content textType="caption" textAlign="left" fontSize="12" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>引擎加载清单</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="325" width="460" height="18">
    <content textType="caption" textAlign="left" fontSize="12" fontFamily="Consolas" color="#5c5c75">
      <p>1. 持久化配置 + 守护天数</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="348" width="460" height="18">
    <content textType="caption" textAlign="left" fontSize="12" fontFamily="Consolas" color="#5c5c75">
      <p>2. 扫描管线 + YARA 规则索引</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="371" width="460" height="18">
    <content textType="caption" textAlign="left" fontSize="12" fontFamily="Consolas" color="#5c5c75">
      <p>3. LRU 扫描缓存初始化</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="394" width="460" height="18">
    <content textType="caption" textAlign="left" fontSize="12" fontFamily="Consolas" color="#5c5c75">
      <p>4. native_guard.dll ctypes 桥接</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="417" width="460" height="18">
    <content textType="caption" textAlign="left" fontSize="12" fontFamily="Consolas" color="#5c5c75">
      <p>5. 自适应线程池 + 性能统计</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="440" width="460" height="18">
    <content textType="caption" textAlign="left" fontSize="12" fontFamily="Consolas" color="#5c5c75">
      <p>6. DEX 字节码解析器</p>
    </content>
  </shape>
</data>
</slide>'''

# ══════════════════════════════════════════════════════════════
#  Slide 4: 持久化存储
# ══════════════════════════════════════════════════════════════
SLIDE4 = '''<slide xmlns="http://www.larkoffice.com/sml/2.0">
<style><fill><fillColor color="#0a0e1a"/></fill></style>
<data>
  <shape type="rect" topLeftX="60" topLeftY="0" width="4" height="540">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="36" width="500" height="50">
    <content textType="title" textAlign="left" fontSize="36" fontFamily="Microsoft YaHei" color="#f4f4f9" bold="true">
      <p>持久化存储架构</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="90" width="60" height="3">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="130" width="240" height="200" cornerRadius="12">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="145" width="200" height="25">
    <content textType="sub-headline" textAlign="left" fontSize="16" fontFamily="Microsoft YaHei" color="#f4f4f9" bold="true">
      <p>config_save.json</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="180" width="200" height="100">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Microsoft YaHei" color="#8f8fab" lineSpacing="1.6">
      <p>扫描配置：线程池、超时、YARA/ML 开关</p>
      <p>防护模块开关</p>
      <p>功能开关</p>
      <p>网络与策略配置</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="360" topLeftY="130" width="240" height="200" cornerRadius="12">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="380" topLeftY="145" width="200" height="25">
    <content textType="sub-headline" textAlign="left" fontSize="16" fontFamily="Microsoft YaHei" color="#f4f4f9" bold="true">
      <p>guard_days.json</p>
    </content>
  </shape>
  <shape type="text" topLeftX="380" topLeftY="180" width="200" height="100">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Microsoft YaHei" color="#8f8fab" lineSpacing="1.6">
      <p>first_start_date 首次启动日期</p>
      <p>last_start_date 上次启动日期</p>
      <p>accumulated_days 累计守护天数</p>
      <p>每日启动自动更新</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="620" topLeftY="130" width="240" height="200" cornerRadius="12">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="640" topLeftY="145" width="200" height="25">
    <content textType="sub-headline" textAlign="left" fontSize="16" fontFamily="Microsoft YaHei" color="#f4f4f9" bold="true">
      <p>scan_cache.db</p>
    </content>
  </shape>
  <shape type="text" topLeftX="640" topLeftY="180" width="200" height="100">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Microsoft YaHei" color="#8f8fab" lineSpacing="1.6">
      <p>SQLite 持久化扫描缓存</p>
      <p>TTL 过期 + LRU 淘汰</p>
      <p>cache_key 索引查询</p>
      <p>自动清理过期条目</p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="360" width="800" height="25">
    <content textType="sub-headline" textAlign="left" fontSize="16" fontFamily="Microsoft YaHei" color="#f4f4f9" bold="true">
      <p>核心机制</p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="395" width="800" height="80">
    <content textType="body" textAlign="left" fontSize="14" fontFamily="Microsoft YaHei" color="#c6c6c6" lineSpacing="1.8">
      <p><span color="#00d9c0">启动加载:</span> config.py 读取持久化配置覆盖默认值，update_guard_days() 对比日期自动累加天数</p>
      <p><span color="#00d9c0">退出保存:</span> atexit 钩子 + shutdown API 双重保障，强制写入所有状态 + 清理过期缓存</p>
      <p><span color="#00d9c0">API 端点:</span> GET/POST /config-save · GET /guard-days · GET /cache/stats · POST /cache/clear</p>
    </content>
  </shape>
</data>
</slide>'''

# ══════════════════════════════════════════════════════════════
#  Slide 5: 退出流程
# ══════════════════════════════════════════════════════════════
SLIDE5 = '''<slide xmlns="http://www.larkoffice.com/sml/2.0">
<style><fill><fillColor color="#0a0e1a"/></fill></style>
<data>
  <shape type="rect" topLeftX="60" topLeftY="0" width="4" height="540">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="36" width="500" height="50">
    <content textType="title" textAlign="left" fontSize="36" fontFamily="Microsoft YaHei" color="#f4f4f9" bold="true">
      <p>统一退出流程</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="90" width="60" height="3">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="rect" topLeftX="65" topLeftY="150" width="170" height="70" cornerRadius="8">
    <fill><fillColor color="#002020"/></fill><border color="#00d9c0" width="1"/>
  </shape>
  <shape type="text" topLeftX="65" topLeftY="162" width="170" height="20">
    <content textType="body" textAlign="center" fontSize="13" fontFamily="Microsoft YaHei" color="#00d9c0" bold="true">
      <p>1. 保存状态</p>
    </content>
  </shape>
  <shape type="text" topLeftX="65" topLeftY="188" width="170" height="20">
    <content textType="body" textAlign="center" fontSize="11" fontFamily="Microsoft YaHei" color="#5c5c75">
      <p>配置 + 守护天数</p>
    </content>
  </shape>
  <line startX="235" startY="185" endX="275" endY="185">
    <border color="#00d9c0" width="2"/>
  </line>
  <shape type="rect" topLeftX="275" topLeftY="150" width="170" height="70" cornerRadius="8">
    <fill><fillColor color="#002020"/></fill><border color="#00d9c0" width="1"/>
  </shape>
  <shape type="text" topLeftX="275" topLeftY="162" width="170" height="20">
    <content textType="body" textAlign="center" fontSize="13" fontFamily="Microsoft YaHei" color="#00d9c0" bold="true">
      <p>2. Logo 退出窗口</p>
    </content>
  </shape>
  <shape type="text" topLeftX="275" topLeftY="188" width="170" height="20">
    <content textType="body" textAlign="center" fontSize="11" fontFamily="Microsoft YaHei" color="#5c5c75">
      <p>停留 200ms 后淡出</p>
    </content>
  </shape>
  <line startX="445" startY="185" endX="485" endY="185">
    <border color="#00d9c0" width="2"/>
  </line>
  <shape type="rect" topLeftX="485" topLeftY="150" width="170" height="70" cornerRadius="8">
    <fill><fillColor color="#002020"/></fill><border color="#00d9c0" width="1"/>
  </shape>
  <shape type="text" topLeftX="485" topLeftY="162" width="170" height="20">
    <content textType="body" textAlign="center" fontSize="13" fontFamily="Microsoft YaHei" color="#00d9c0" bold="true">
      <p>3. 淡出动画</p>
    </content>
  </shape>
  <shape type="text" topLeftX="485" topLeftY="188" width="170" height="20">
    <content textType="body" textAlign="center" fontSize="11" fontFamily="Microsoft YaHei" color="#5c5c75">
      <p>600ms 渐隐到透明</p>
    </content>
  </shape>
  <line startX="655" startY="185" endX="695" endY="185">
    <border color="#00d9c0" width="2"/>
  </line>
  <shape type="rect" topLeftX="695" topLeftY="150" width="170" height="70" cornerRadius="8">
    <fill><fillColor color="#002020"/></fill><border color="#00d9c0" width="1"/>
  </shape>
  <shape type="text" topLeftX="695" topLeftY="162" width="170" height="20">
    <content textType="body" textAlign="center" fontSize="13" fontFamily="Microsoft YaHei" color="#00d9c0" bold="true">
      <p>4. 资源释放</p>
    </content>
  </shape>
  <shape type="text" topLeftX="695" topLeftY="188" width="170" height="20">
    <content textType="body" textAlign="center" fontSize="11" fontFamily="Microsoft YaHei" color="#5c5c75">
      <p>缓存 + DLL 引用</p>
    </content>
  </shape>
  <line startX="865" startY="185" endX="905" endY="185">
    <border color="#00d9c0" width="2"/>
  </line>
  <shape type="rect" topLeftX="65" topLeftY="260" width="810" height="60" cornerRadius="8">
    <fill><fillColor color="#131320"/></fill><border color="#00d9c0" width="2"/>
  </shape>
  <shape type="text" topLeftX="65" topLeftY="270" width="810" height="40">
    <content textType="headline" textAlign="center" fontSize="24" fontFamily="Consolas" color="#00d9c0" bold="true">
      <p>os._exit(0)</p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="360" width="800" height="30">
    <content textType="body" textAlign="left" fontSize="14" fontFamily="Microsoft YaHei" color="#c6c6c6">
      <p><span color="#00d9c0" bold="true">触发路径:</span> 窗口关闭按钮 / 托盘退出菜单 / API POST /shutdown <span color="#8f8fab">— 三条路径统一调用 _do_exit_with_fadeout()</span></p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="400" width="800" height="50">
    <content textType="body" textAlign="left" fontSize="14" fontFamily="Microsoft YaHei" color="#c6c6c6" lineSpacing="1.8">
      <p><span color="#00d9c0" bold="true">技术要点:</span> Logo 淡出动画在独立线程中运行，资源释放与动画并行执行</p>
      <p>atexit 钩子作为最后防线，确保异常退出也能保存关键状态</p>
    </content>
  </shape>
</data>
</slide>'''

# ══════════════════════════════════════════════════════════════
#  Slide 6: 引擎架构
# ══════════════════════════════════════════════════════════════
SLIDE6 = '''<slide xmlns="http://www.larkoffice.com/sml/2.0">
<style><fill><fillColor color="#0a0e1a"/></fill></style>
<data>
  <shape type="rect" topLeftX="60" topLeftY="0" width="4" height="540">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="36" width="500" height="50">
    <content textType="title" textAlign="left" fontSize="36" fontFamily="Microsoft YaHei" color="#f4f4f9" bold="true">
      <p>引擎架构全景</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="90" width="60" height="3">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="120" width="380" height="380" cornerRadius="12">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="130" width="340" height="25">
    <content textType="headline" textAlign="left" fontSize="18" fontFamily="Microsoft YaHei" color="#00d9c0" bold="true">
      <p>扫描引擎层</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="165" width="340" height="18">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Consolas" color="#8f8fab">
      <p>  YARA 规则扫描 (100+ 条规则)</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="190" width="340" height="18">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Consolas" color="#8f8fab">
      <p>  ML PE 扫描 (EMBER 2381维)</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="215" width="340" height="18">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Consolas" color="#8f8fab">
      <p>  启发式打分 (native_engine.exe)</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="240" width="340" height="18">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Consolas" color="#8f8fab">
      <p>  DEX 解析器 (AndroRat/iBanking)</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="265" width="340" height="18">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Consolas" color="#8f8fab">
      <p>  云端 ThreatBook 联动</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="120" topLeftY="293" width="340" height="1">
    <fill><fillColor color="#252536"/></fill>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="302" width="340" height="25">
    <content textType="headline" textAlign="left" fontSize="18" fontFamily="Microsoft YaHei" color="#00d9c0" bold="true">
      <p>原生对抗层 (native_guard.dll)</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="335" width="340" height="18">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Consolas" color="#8f8fab">
      <p>  进程注入对抗 (内存/模块/线程)</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="360" width="340" height="18">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Consolas" color="#8f8fab">
      <p>  无文件攻击检测 (LOLBins/WMI)</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="385" width="340" height="18">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Consolas" color="#8f8fab">
      <p>  持久化木马巡检 (8+ 通道)</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="410" width="340" height="18">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Consolas" color="#8f8fab">
      <p>  网络外联检测 (TCP/C2匹配)</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="435" width="340" height="18">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Consolas" color="#8f8fab">
      <p>  AMSI 无文件拦截 / ETW 事中检测</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="460" width="340" height="18">
    <content textType="body" textAlign="left" fontSize="12" fontFamily="Consolas" color="#8f8fab">
      <p>  游戏模式自适应降频</p>
    </content>
  </shape>
  <shape type="text" topLeftX="520" topLeftY="120" width="380" height="25">
    <content textType="headline" textAlign="left" fontSize="18" fontFamily="Microsoft YaHei" color="#00d9c0" bold="true">
      <p>基础架构 &amp; 辅助功能</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="520" topLeftY="155" width="180" height="50" cornerRadius="8">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="530" topLeftY="160" width="160" height="40">
    <content textType="body" textAlign="center" fontSize="14" fontFamily="Microsoft YaHei" color="#f4f4f9">
      <p>pywebview 窗口容器</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="720" topLeftY="155" width="180" height="50" cornerRadius="8">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="730" topLeftY="160" width="160" height="40">
    <content textType="body" textAlign="center" fontSize="14" fontFamily="Microsoft YaHei" color="#f4f4f9">
      <p>Logo 启动画面</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="520" topLeftY="215" width="180" height="50" cornerRadius="8">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="530" topLeftY="220" width="160" height="40">
    <content textType="body" textAlign="center" fontSize="14" fontFamily="Microsoft YaHei" color="#f4f4f9">
      <p>持久化存储 (3 文件)</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="720" topLeftY="215" width="180" height="50" cornerRadius="8">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="730" topLeftY="220" width="160" height="40">
    <content textType="body" textAlign="center" fontSize="14" fontFamily="Microsoft YaHei" color="#f4f4f9">
      <p>atexit 退出保存</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="520" topLeftY="275" width="380" height="30" cornerRadius="8">
    <fill><fillColor color="#131320"/></fill>
  </shape>
  <shape type="text" topLeftX="530" topLeftY="278" width="360" height="24">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>  WebSocket 实时进度 · 漏洞筛查 · 隔离区管理</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="520" topLeftY="310" width="380" height="30" cornerRadius="8">
    <fill><fillColor color="#131320"/></fill>
  </shape>
  <shape type="text" topLeftX="530" topLeftY="313" width="360" height="24">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>  系统托盘 · 开机自启 · 右键菜单 · USB扫描</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="520" topLeftY="345" width="380" height="30" cornerRadius="8">
    <fill><fillColor color="#131320"/></fill>
  </shape>
  <shape type="text" topLeftX="530" topLeftY="348" width="360" height="24">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>  Vigil 强力模式 · P2P 内网穿透 · 深度分析</p>
    </content>
  </shape>
</data>
</slide>'''

# ══════════════════════════════════════════════════════════════
#  Slide 7: 结尾
# ══════════════════════════════════════════════════════════════
SLIDE7 = '''<slide xmlns="http://www.larkoffice.com/sml/2.0">
<style><fill><fillColor color="linear-gradient(135deg,rgba(10,14,26,1) 0%,rgba(0,40,40,1) 100%)"/></fill></style>
<data>
  <shape type="rect" topLeftX="60" topLeftY="0" width="4" height="540">
    <fill><fillColor color="#00d9c0"/></fill>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="130" width="800" height="80">
    <content textType="title" textAlign="left" fontSize="44" fontFamily="Microsoft YaHei" color="#f4f4f9" bold="true">
      <p>安盾持续演进，<span color="#00d9c0">守护每一次点击</span></p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="230" width="800" height="30">
    <content textType="body" textAlign="left" fontSize="16" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>从扫描引擎到原生对抗，从启动画面到持久化存储 — 每一行代码都为安全而生</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="290" width="800" height="1">
    <fill><fillColor color="#252536"/></fill>
  </shape>
  <shape type="rect" topLeftX="100" topLeftY="320" width="240" height="120" cornerRadius="12">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="335" width="200" height="25">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>引擎版本</p>
    </content>
  </shape>
  <shape type="text" topLeftX="120" topLeftY="365" width="200" height="50">
    <content textType="headline" textAlign="left" fontSize="36" fontFamily="Consolas" color="#00d9c0" bold="true">
      <p>1.0.2</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="370" topLeftY="320" width="240" height="120" cornerRadius="12">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="390" topLeftY="335" width="200" height="25">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>扫描引擎</p>
    </content>
  </shape>
  <shape type="text" topLeftX="390" topLeftY="365" width="200" height="50">
    <content textType="headline" textAlign="left" fontSize="36" fontFamily="Consolas" color="#00d9c0" bold="true">
      <p>5 层</p>
    </content>
  </shape>
  <shape type="rect" topLeftX="640" topLeftY="320" width="240" height="120" cornerRadius="12">
    <fill><fillColor color="#131320"/></fill><border color="#252536" width="1"/>
  </shape>
  <shape type="text" topLeftX="660" topLeftY="335" width="200" height="25">
    <content textType="body" textAlign="left" fontSize="13" fontFamily="Microsoft YaHei" color="#8f8fab">
      <p>原生对抗</p>
    </content>
  </shape>
  <shape type="text" topLeftX="660" topLeftY="365" width="200" height="50">
    <content textType="headline" textAlign="left" fontSize="36" fontFamily="Consolas" color="#00d9c0" bold="true">
      <p>8 模块</p>
    </content>
  </shape>
  <shape type="text" topLeftX="100" topLeftY="470" width="800" height="30">
    <content textType="body" textAlign="left" fontSize="14" fontFamily="Microsoft YaHei" color="#5c5c75">
      <p>安盾 · 2026年8月 · 感谢使用</p>
    </content>
  </shape>
</data>
</slide>'''

SLIDES = [SLIDE1, SLIDE2, SLIDE3, SLIDE4, SLIDE5, SLIDE6, SLIDE7]

def main():
    """逐页创建幻灯片"""
    print(f"Presentation ID: {PRESENTATION_ID}")

    for i, slide_xml in enumerate(SLIDES):
        print(f"\n--- Creating Slide {i+1} ---")

        data = json.dumps({"slide": {"content": slide_xml}}, ensure_ascii=False)
        params = json.dumps({"xml_presentation_id": PRESENTATION_ID})

        stdout, stderr, rc = run_lark(
            "slides", "xml_presentation.slide", "create",
            "--as", "user",
            "--params", params,
            "--data", data,
            "--json"
        )

        result = stdout.strip()
        if result:
            try:
                parsed = json.loads(result)
                ok = parsed.get("ok", False)
                if ok:
                    slide_id = parsed.get("data", {}).get("slide_id", "?")
                    print(f"  OK: slide_id={slide_id}")
                else:
                    err = parsed.get("error", {}).get("message", result)
                    print(f"  FAIL: {err}")
            except json.JSONDecodeError:
                print(f"  Output: {stdout[:200]}")
        else:
            print(f"  No output. stderr: {stderr[:200]}")

    print("\nDone!")

if __name__ == "__main__":
    main()
