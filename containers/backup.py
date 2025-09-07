#!/usr/bin/env python3
"""
Vaultwarden 备份脚本（内存日志 + 推送 + 阿里云 OSS 上传）
- 日志不写磁盘，使用 InMemoryHandler 缓冲
- push_log() 会把缓冲内容 POST 到 PUSH_URL（需要 PUSH_TOKEN）
- 保留 console 输出（方便容器日志收集）
"""

from __future__ import annotations

import os
import sys
import logging
import tarfile
import subprocess
import time
import re
from pathlib import Path
from datetime import datetime, timedelta
import urllib.parse
import urllib.request
from collections import deque
from threading import Lock
from typing import List, Optional
import tempfile
import alibabacloud_oss_v2 as oss

# 配置（从环境读取，提供默认）
BACKUP_NAME = os.getenv("BACKUP_NAME", "vaultwarden")
RUN_TITLE = "Vaultwarden备份"
BACKUP_PATH = os.getenv("BACKUP_PATH", "/vw/data")
ENCRYPTION_PUB_ID = os.getenv("ENCRYPTION_PUB_ID")
ENCRYPTION_PUB_KEY = os.getenv("ENCRYPTION_PUB_KEY")
OSS_ACCESS_KEY_ID = os.getenv("OSS_ACCESS_KEY_ID")
OSS_ACCESS_KEY_SECRET = os.getenv("OSS_ACCESS_KEY_SECRET")
OSS_BUCKET = os.getenv("OSS_BUCKET")
OSS_REGION = os.getenv("OSS_REGION")
PUSH_URL = os.getenv("PUSH_URL")
PUSH_TOKEN = os.getenv("PUSH_TOKEN")
MEM_LOG_CAPACITY = int(os.getenv("MEM_LOG_CAPACITY", "5000"))
DAYS_TO_KEEP = int(os.getenv("DAYS_TO_KEEP", "7"))  # 新增：从环境变量读取保留天数

# ----------------- 内存日志 Handler -----------------
class InMemoryHandler(logging.Handler):
    """将格式化后的日志行缓存在内存 deque 中（线程安全）。"""

    def __init__(self, capacity: int = 5000) -> None:
        super().__init__(level=logging.NOTSET)
        self._buffer: deque[str] = deque(maxlen=capacity)
        self._lock: Lock = Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            with self._lock:
                self._buffer.append(msg)
        except Exception:
            pass  # 静默失败，避免影响主流程

    def get_logs(self) -> str:
        with self._lock:
            return "\n".join(self._buffer)

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()

# 日志配置
stream_handler = logging.StreamHandler(sys.stdout)
mem_handler = InMemoryHandler(capacity=MEM_LOG_CAPACITY)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
stream_handler.setFormatter(formatter)
mem_handler.setFormatter(formatter)
logging.basicConfig(level=logging.INFO, handlers=[stream_handler, mem_handler])
logger = logging.getLogger(__name__)

# ----------------- 工具函数 -----------------
def now_date_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")

def safe_subprocess_run(args: List[str], input_data: Optional[bytes] = None, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=input_data, **kwargs)

def send_message_stdlib(title: str, description: str, content: str,
                        push_url: Optional[str] = None, push_token: Optional[str] = None,
                        timeout: float = 5.0) -> bool:
    url = push_url or PUSH_URL
    token = push_token or PUSH_TOKEN
    if not url or not token:
        logger.info("PUSH_URL 或 PUSH_TOKEN 未设置，跳过推送")
        return False

    data = {"title": title, "description": description, "content": content, "token": token}
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=encoded, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.getcode() < 400
    except Exception:
        logger.exception("发送推送消息失败")
        return False

def push_log() -> bool:
    if not PUSH_URL or not PUSH_TOKEN:
        logger.info("日志推送: PUSH_URL 或 PUSH_TOKEN 未设置，跳过")
        return False

    log_text = mem_handler.get_logs()
    # 优化：将日志包装为Markdown代码块，以保留换行和格式
    markdown_content = f"```\n{log_text}\n```"
    ok = send_message_stdlib(RUN_TITLE, RUN_TITLE, markdown_content)
    if ok:
        logger.info("日志推送成功")
        mem_handler.clear()
    else:
        logger.warning("日志推送失败")
    return ok

def clean_tmp() -> None:
    logger.info("清理临时文件")
    for p in Path("/tmp").glob(f"{BACKUP_NAME}_*.enc"):
        try:
            p.unlink()
            logger.info("删除临时加密文件: %s", p)
        except Exception:
            logger.exception("删除临时加密文件失败: %s", p)

def handle_error(msg: str, exit_code: int = 1) -> None:
    logger.error("错误: %s", msg)
    push_log()
    clean_tmp()
    sys.exit(exit_code)

# ----------------- 环境与 GPG -----------------
def check_envs() -> None:
    missing = []
    for var in ["OSS_ACCESS_KEY_ID", "OSS_ACCESS_KEY_SECRET", "OSS_BUCKET", "OSS_REGION",
                "ENCRYPTION_PUB_ID", "ENCRYPTION_PUB_KEY"]:
        if not os.getenv(var):
            missing.append(var)
    if missing:
        raise EnvironmentError("缺少必要环境变量: " + ", ".join(missing))

def handle_gpg_key() -> None:
    if not ENCRYPTION_PUB_ID or not ENCRYPTION_PUB_KEY:
        raise EnvironmentError("GPG 公钥或 ID 未配置")

    try:
        res = safe_subprocess_run(["gpg", "--list-keys", ENCRYPTION_PUB_ID],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            logger.info("密钥 %s 已存在，无需导入", ENCRYPTION_PUB_ID)
            return

        logger.info("导入公钥 %s ...", ENCRYPTION_PUB_ID)
        proc = safe_subprocess_run(["gpg", "--trust-model", "always", "--import"],
                                   input_data=ENCRYPTION_PUB_KEY.encode("utf-8"),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        logger.info("GPG 导入完成")
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode(errors="ignore") if e.stderr else ""
        logger.error("GPG 导入失败: %s", stderr)
        raise RuntimeError("GPG 导入失败")
    except FileNotFoundError:
        handle_error("系统未找到 gpg 命令，请安装 gnupg")
    except Exception:
        logger.exception("处理 GPG 密钥时出错")
        raise

# ----------------- 打包与加密 -----------------
def create_tar_gz(source_dir: str, out_path: Path) -> None:
    logger.info("开始打包 %s -> %s", source_dir, out_path)
    source = Path(source_dir)
    if not source.exists() or not source.is_dir():
        raise FileNotFoundError(f"备份源不存在或非目录: {source_dir}")
    with tarfile.open(out_path, "w:gz") as tar:
        for item in source.iterdir():
            tar.add(item, arcname=item.name)
    logger.info("打包完成: %s", out_path)

def gpg_encrypt_file(input_path: Path, output_path: Path, recipient: str) -> None:
    logger.info("使用 GPG 加密 %s -> %s (recipient=%s)", input_path, output_path, recipient)
    safe_subprocess_run([
        "gpg", "--yes", "--batch", "--trust-model", "always",
        "--recipient", recipient, "--encrypt", "--output", str(output_path), str(input_path)
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

# ----------------- 阿里云 OSS 操作封装 -----------------
def _oss_client() -> oss.Client:
    try:
        credentials_provider = oss.credentials.EnvironmentVariableCredentialsProvider()
        cfg = oss.config.load_default()
        cfg.credentials_provider = credentials_provider
        if OSS_REGION:
            cfg.region = OSS_REGION
        return oss.Client(cfg)
    except Exception:
        logger.exception("创建 OSS client 失败")
        raise

def oss_upload(local_path: Path, remote_key: str) -> bool:
    if not local_path.exists():
        logger.error("待上传文件不存在: %s", local_path)
        return False

    client = _oss_client()
    uploader = client.uploader(part_size=100 * 1024, parallel_num=5, leave_parts_on_error=True)
    try:
        result = uploader.upload_file(
            oss.PutObjectRequest(bucket=OSS_BUCKET, key=remote_key),
            filepath=str(local_path)
        )
        status = result.status_code
        logger.info("上传返回状态: %s", status)
        return 200 <= status < 300
    except Exception:
        logger.exception("OSS 上传失败")
        return False

def oss_list_objects(prefix: str) -> List[str]:
    client = _oss_client()
    paginator = client.list_objects_v2_paginator()
    keys: List[str] = []
    req = oss.ListObjectsV2Request(bucket=OSS_BUCKET, prefix=prefix)
    try:
        for page in paginator.iter_page(req):
            if page.contents:
                for o in page.contents:
                    keys.append(o.key)
        return keys
    except Exception:
        logger.exception("列出 OSS 对象失败")
        raise

def oss_delete_object(object_key: str) -> bool:
    client = _oss_client()
    try:
        result = client.delete_object(oss.DeleteObjectRequest(bucket=OSS_BUCKET, key=object_key))
        status = result.status_code
        logger.info("删除 %s 返回状态 %s", object_key, status)
        return 200 <= status < 300
    except Exception:
        logger.exception("删除 OSS 对象失败: %s", object_key)
        return False

# ----------------- 备份与清理主逻辑 -----------------
def perform_backup() -> None:
    timestamp = now_date_str()
    remote_key = f"file/{BACKUP_NAME}_{timestamp}.enc"
    source_path = Path(BACKUP_PATH)

    logger.info("开始备份 %s 目录", source_path)
    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_tar = Path(tmp_dir) / f"{BACKUP_NAME}_temp.tar.gz"
        backup_file = Path(tmp_dir) / f"{BACKUP_NAME}_{timestamp}.enc"

        try:
            create_tar_gz(str(source_path), temp_tar)
            gpg_encrypt_file(temp_tar, backup_file, ENCRYPTION_PUB_ID)
        except Exception as e:
            handle_error(f"备份打包或加密失败: {e}")

        max_retries = 3
        retry_delay = 5
        for attempt in range(1, max_retries + 1):
            logger.info("上传备份到 OSS: 尝试 %d/%d", attempt, max_retries)
            if oss_upload(backup_file, remote_key):
                logger.info("备份上传成功: %s", remote_key)
                return
            if attempt < max_retries:
                time.sleep(retry_delay)

    handle_error(f"上传失败，已达最大重试次数 {max_retries}")

def clean_old_backups(days_to_keep: int) -> None:
    logger.info("开始清理 %d 天前的旧备份", days_to_keep)
    cutoff_date = datetime.now() - timedelta(days=days_to_keep)
    prefix = f"file/{BACKUP_NAME}_"
    date_re = re.compile(rf"{re.escape(BACKUP_NAME)}_([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})\.enc$")

    try:
        objects = oss_list_objects(prefix)
    except Exception:
        logger.exception("列出 OSS 对象失败，跳过旧备份清理")
        return

    for obj_key in objects:
        name = obj_key.split("/")[-1]
        m = date_re.search(name)
        if not m:
            continue
        try:
            file_date = datetime.strptime(m.group(1), "%Y-%m-%d")
            if file_date < cutoff_date:
                logger.info("删除旧备份: %s", name)
                if not oss_delete_object(obj_key):
                    logger.warning("删除 %s 失败", obj_key)
        except ValueError:
            logger.warning("无效日期格式: %s", name)

    logger.info("旧备份清理完成")

# ----------------- 主入口 -----------------
def main() -> None:
    clean_tmp()
    try:
        check_envs()
        handle_gpg_key()
        perform_backup()
        clean_old_backups(DAYS_TO_KEEP)
        push_log()
    except Exception as e:
        handle_error(f"未处理的异常: {e}")
    finally:
        clean_tmp()

if __name__ == "__main__":
    main()