#!/bin/bash
set -eu

# 备份设置
BACKUP_PATH=/data
BACKUP_NAME="vaultwarden"

# 调试模式标志（默认关闭）
DEBUG_MODE=${DEBUG_MODE:-0}

# OSS配置
OSSCONFIG=${OSSCONFIG:-/tmp/ossconfig}

# 全局日志
RUN_TITLE="Vaultwarden备份"

clean_tmp() {
	# 清理临时文件
	rm -f /tmp/ossconfig
	rm -f /tmp/${BACKUP_NAME}_*.enc
	rm -f /tmp/run.log
}

# 日志输出
log() {
	local message="$(date '+%Y-%m-%d %H:%M:%S') - $1"

	if [ "${DEBUG_MODE}" -eq 1 ]; then
		# 调试日志
		echo "[DEBUG] ${message}" >&2
		# 全局日志
		echo "" >> /tmp/run.log
		echo "[DEBUG] ${message}" >> /tmp/run.log
	else
		# Docker日志
		echo "[BACKUP] ${message}" >/proc/1/fd/1 2>/proc/1/fd/2
		# 全局日志
		echo "" >> /tmp/run.log
		echo "[BACKUP] ${message}" >> /tmp/run.log
	fi
}

send_message() {
  # POST Form
  curl -s -X POST "$PUSH_URL" \
    -d "title=${1}&description=${2}&content=${3}&token=$PUSH_TOKEN" \
    >/dev/null
}

# 日志推送
push_log() {
	for var in PUSH_URL PUSH_TOKEN; do
		if [ -z "${!var:-}" ]; then
			log "日志推送: 必须的环境变量 ${var} 未设置"
			return 0
		fi
	done

	RUN_LOG="$(</tmp/run.log)"
	send_message "${RUN_TITLE}" "${RUN_TITLE}" "${RUN_LOG}"
}

# 错误处理函数
handle_error() {
	log "错误: $1"
	push_log
	clean_tmp
	exit 1
}

# 解析命令行参数
parse_args() {
	if [ "${DEBUG_MODE}" -eq 1 ]; then
		while getopts "c:" opt; do
			case ${opt} in
			c)
				OSSCONFIG="${OPTARG}"
				log "使用自定义OSS配置文件: ${OSSCONFIG}"
				;;
			*)
				handle_error "无效选项: -${OPTARG}"
				;;
			esac
		done
	fi
}

# 检查环境变量
check_env() {
	# 调试模式下跳过GPG密钥处理
	if [ "${DEBUG_MODE}" -eq 1 ]; then
		log "调试模式: 跳过环境变量"
		return 0
	fi

	for var in OSS_ACCESSKEY_SECRET OSS_ENDPOINT OSS_ACCESSKEY_ID \
		ENCRYPTION_PUB_ID ENCRYPTION_PUB_KEY; do
		if [ -z "${!var:-}" ]; then
			handle_error "备份脚本: 必须的环境变量 ${var} 未设置"
		fi
	done
}

# 配置OSS
configure_oss() {
	# 调试模式下使用现有配置或自定义路径
	if [ "${DEBUG_MODE}" -eq 1 ]; then
		if [ -f "${OSSCONFIG}" ]; then
			log "调试模式: 使用现有OSS配置文件: ${OSSCONFIG}"
			return 0
		else
			handle_error "调试模式下未找到OSS配置文件: ${OSSCONFIG}"
		fi
	fi

	# 非调试模式创建默认配置
	cat <<EOF >"${OSSCONFIG}"
[Credentials]
language=CH
accessKeySecret=${OSS_ACCESSKEY_SECRET}
endpoint=${OSS_ENDPOINT}
accessKeyID=${OSS_ACCESSKEY_ID}
EOF
	chmod 600 "${OSSCONFIG}"
}

# 处理GPG密钥
handle_gpg_key() {
	# 调试模式下跳过GPG密钥处理
	if [ "${DEBUG_MODE}" -eq 1 ]; then
		log "调试模式: 跳过GPG密钥处理"
		return 0
	fi

	if gpg --fingerprint "${ENCRYPTION_PUB_ID}" >/dev/null 2>&1; then
		log "密钥 ${ENCRYPTION_PUB_ID} 已存在,无须导入."
	else
		log "密钥 ${ENCRYPTION_PUB_ID} 未导入,导入中..."
		if ! echo "${ENCRYPTION_PUB_KEY}" | gpg --import; then
			handle_error "GPG密钥导入失败"
		fi
		if [ -f "/gpg.sh" ] && ! expect -f /gpg.sh; then
			handle_error "GPG密钥信任设置失败"
		fi
	fi
}

# 执行备份
perform_backup() {
	# 调试模式下跳过实际备份操作
	if [ "${DEBUG_MODE}" -eq 1 ]; then
		log "调试模式: 跳过实际备份操作"
		return 0
	fi

	timestamp=$(date +'%Y-%m-%d')
	backup_file="/tmp/${BACKUP_NAME}_${timestamp}.enc"
	temp_file="/tmp/${BACKUP_NAME}_temp.tar.gz"

	log "开始备份 ${BACKUP_PATH} 目录"
	if ! tar -zcvf "${temp_file}" -C ${BACKUP_PATH} .; then
		rm -f "${temp_file}"
		handle_error "备份打包失败"
	fi

	if ! gpg --recipient "${ENCRYPTION_PUB_ID}" --encrypt --output "${backup_file}" "${temp_file}"; then
		rm -f "${temp_file}"
		handle_error "备份加密失败"
	fi

	rm -f "${temp_file}"

	log "上传备份到 OSS"
	max_retries=3
	retry_count=0

	while [ "${retry_count}" -lt "${max_retries}" ]; do
		if ossutil cp "${backup_file}" "oss://my-server-backup/file/" -f \
			-c "${OSSCONFIG}" \
			--maxupspeed 4096; then
			log "备份成功: ${BACKUP_NAME}_${timestamp}.enc"
			rm -f "${backup_file}"
			return 0
		fi

		retry_count=$((retry_count + 1))
		log "上传尝试 ${retry_count} 失败，正在重试..."
		sleep 5
	done

	handle_error "上传失败，已达最大重试次数 ${max_retries}"
}

# 清理旧备份(保留最近7天)
clean_old_backups() {
	log "开始清理7天前的旧备份"
	cutoff_date=$(date -d "7 days ago" +'%Y-%m-%d')

	if ! backup_list=$(ossutil ls oss://my-server-backup/file/ --include ${BACKUP_NAME}_* -c "$OSSCONFIG"); then
		handle_error "获取备份列表失败"
	fi

	# 使用awk直接处理原始输出
	echo "${backup_list}" | awk -v backup_name="${BACKUP_NAME}" '{
    for(i=1; i<=NF; i++) {
        if ($i ~ "^oss://.*" backup_name "_[0-9]{4}-[0-9]{2}-[0-9]{2}\\.enc") {
            print $i
        }
    }
}' | while read -r object; do
		file_date=$(echo "${object}" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}')

		if [ -n "${file_date}" ] && [ "${file_date}" \< "${cutoff_date}" ]; then
			log "删除旧备份: '${BACKUP_NAME}_${file_date}.enc'"
			if ! ossutil rm "${object}" -c "${OSSCONFIG}" >/dev/null 2>&1; then
				log "警告: 删除 '${BACKUP_NAME}_${file_date}.enc' 失败"
			fi
		fi
	done

	log "旧备份清理完成"
}

oss_check() {
	# 检查OSS连接
	if ! ossutil ls oss://my-server-backup -c "${OSSCONFIG}" >/dev/null; then
		handle_error "无法连接到OSS存储桶，请检查凭证"
	fi
}

ossutil_check() {
	if ! command -v ossutil >/dev/null 2>&1; then
    	handle_error "错误: ossutil 未安装，请先安装该工具"
	fi
}

# 主流程
main() {
	# 清理临时文件
	clean_tmp
	touch /tmp/run.log
	# 解析参数
	parse_args "$@"
	# 检查参数数量
	if [ "$#" -lt "$OPTIND" ]; then
		log "执行参数: 未提供任何有效参数，使用默认配置"
	fi
	# 调整参数指针
	shift $((OPTIND - 1))
	# 检查oss工具
	ossutil_check
	# 检查环境变量
	check_env
	# 配置加密密钥
	handle_gpg_key
	# 配置ossutil工具
	configure_oss
	#OSS连接性检查
	oss_check
	# 开始备份
	perform_backup
	# 清理OSS旧备份
	clean_old_backups
	# 日志通知
	push_log
	# 清理临时文件
	clean_tmp
}

main "$@"
exit 0
