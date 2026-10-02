#!/usr/bin/env bash
# 本地验证脚本：不依赖外部网络。
# 日志按“业务模块 -> 用例”分组打印，便于看出覆盖了哪些业务及其结果。
set -euo pipefail
cd "$(dirname "$0")/.."

RACE=""
if [[ "${1:-}" == "-race" ]]; then
  export CGO_ENABLED=1
  RACE="-race"
fi

echo "================================================================"
echo " 出口网络策略代理 · 本地单测（无外部网络依赖）"
echo "================================================================"

run() {
  local title="$1"; shift
  echo
  echo "▶ 业务：${title}"
  echo "----------------------------------------------------------------"
  go test $RACE -v "$@" 2>&1 | grep -E \
    '=== RUN|--- PASS|--- FAIL|^PASS|^FAIL|^ok|业务|拒绝解释|防绕过|超时请求|并发结束|端到端统计|如预期|失败原因' \
    | sed -E 's/^=== RUN/    用例 /; s/^    --- (PASS|FAIL)/         [\1]/; s/^--- (PASS|FAIL)/  [\1] 包/' \
    || true
}

run "策略格式校验与畸形规则整体拒绝"   ./internal/policy/ -run 'TestParseMalformedPolicy|TestParseValidPolicy'
run "域名匹配（精确/子域/单层通配）"    ./internal/policy/ -run 'TestDomainMatching'
run "规则冲突唯一判定与生效规则解释"    ./internal/policy/ -run 'TestConflict|TestDefaultAction'
run "热更新原子性、失败回退与并发快照"  ./internal/policy/ -run 'TestReloadAtomicAndFallback|TestStoreConcurrentReload'
run "HTTP转发：放行/拒绝/统计与可解释"  ./internal/proxy/ -run 'TestHTTPPlainAllowAndDeny'
run "防解析差异绕过（域名允许IP拒绝）"  ./internal/proxy/ -run 'TestDomainAllowedButResolvedIPDenied|TestIPLiteral'
run "错误分类（DNS/不可达/超时/畸形）"  ./internal/proxy/ -run 'TestErrorClassification'
run "HTTPS CONNECT 判定与防绕过"        ./internal/proxy/ -run 'TestHTTPSConnectPolicy'
run "高并发请求×热更：竞态/泄漏/计数"   ./internal/proxy/ -run 'TestConcurrentRequestsAndReload'
run "统计并发守恒"                      ./internal/stats/
run "端到端：启动拦截/热更/管理接口"    ./internal/server/

echo
echo "================================================================"
echo " 汇总（含编译与 vet）"
echo "================================================================"
go vet ./...
go test $RACE -count=1 ./...
echo "全部业务用例通过"
