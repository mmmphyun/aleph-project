#!/usr/bin/env bash
set -euo pipefail

# 실제 요청은 숫자형 loopback으로 제한한다. DNS와 프록시를 거치지 않아 승인되지 않은 대상에 닿지 않는다.
# 경로 후보와 도구 인자는 고정 배열이며 응답 본문, 인증 정보, 원시 도구 출력은 증거에 남기지 않는다.
readonly -a PATHS=(admin login dashboard api health backup config robots.txt sitemap.xml
  uploads images static assets private internal debug status metrics old test)
readonly MAX_CANDIDATES=${#PATHS[@]}

usage() {
  printf '사용법: %s --url http://127.0.0.1:PORT [--tool curl|gobuster] [--candidates 1..20 | --paths admin,login,...] [--interval 0..11] [--max-runtime 1..300] [--concurrency 1..4] [--timeout 1..10] [--evidence PATH] [--execute]\n' "$0" >&2
}

fail_usage() {
  printf '입력 오류: %s\n' "$1" >&2
  usage
  exit 2
}

bounded_number() {
  local value=$1 min=$2 max=$3
  [[ $value =~ ^[1-9][0-9]*$ ]] && ((${#value} <= 5)) && ((10#$value >= min && 10#$value <= max))
}

url='' tool=curl candidates=10 concurrency=1 request_timeout=3 evidence='' execute=0
paths_input='' paths_set=0 candidates_set=0 interval=0 max_runtime=205
while (($#)); do
  case $1 in
    --url|--tool|--candidates|--concurrency|--timeout|--evidence|--paths|--interval|--max-runtime)
      (($# >= 2)) || fail_usage "$1 값이 없습니다"
      case $1 in
        --url) url=$2 ;;
        --tool) tool=$2 ;;
        --candidates) candidates=$2; candidates_set=1 ;;
        --paths) paths_input=$2; paths_set=1 ;;
        --interval) interval=$2 ;;
        --max-runtime) max_runtime=$2 ;;
        --concurrency) concurrency=$2 ;;
        --timeout) request_timeout=$2 ;;
        --evidence) evidence=$2 ;;
      esac
      shift 2 ;;
    --execute) execute=1; shift ;;
    *) fail_usage '알 수 없는 옵션입니다' ;;
  esac
done

[[ $tool == curl || $tool == gobuster ]] || fail_usage '도구는 curl 또는 gobuster만 허용합니다'
bounded_number "$candidates" 1 "$MAX_CANDIDATES" || fail_usage '후보 수는 1..20입니다'
bounded_number "$concurrency" 1 4 || fail_usage '동시성은 1..4입니다'
bounded_number "$request_timeout" 1 10 || fail_usage '요청 제한 시간은 1..10초입니다'
[[ $tool != curl || $concurrency == 1 ]] || fail_usage 'curl 동시성은 1만 허용합니다'
[[ $interval == 0 ]] || bounded_number "$interval" 1 11 || fail_usage '간격은 0..11초입니다'
bounded_number "$max_runtime" 1 300 || fail_usage '전체 실행 한도는 1..300초입니다'
[[ $tool == curl || ( $paths_set == 0 && $interval == 0 ) ]] || fail_usage '경로 순서와 간격 지정은 curl 전용입니다'

# 정책을 복제하지 않고 기존 합성 후보만 재조합한다. 중복은 요청 계획에 보존하며 고유 경로로 세지 않는다.
# 입력은 최대 20개·512자로 제한하고 자격증명/쿼리/임의 경로는 허용하지 않는다.
REQUEST_PATHS=("${PATHS[@]:0:candidates}")
if ((paths_set)); then
  ((candidates_set == 0)) || fail_usage '경로 목록과 후보 수를 함께 지정할 수 없습니다'
  [[ ${#paths_input} -le 512 && $paths_input =~ ^[a-z.]+(,[a-z.]+)*$ ]] || fail_usage '경로 목록 형식이 올바르지 않습니다'
  IFS=, read -r -a REQUEST_PATHS <<< "$paths_input"
  candidates=${#REQUEST_PATHS[@]}
  bounded_number "$candidates" 1 "$MAX_CANDIDATES" || fail_usage '요청 수는 1..20입니다'
  for path in "${REQUEST_PATHS[@]}"; do
    allowed=0
    for candidate in "${PATHS[@]}"; do
      [[ $path != "$candidate" ]] || allowed=1
    done
    ((allowed)) || fail_usage '기존 합성 후보만 지정할 수 있습니다'
  done
fi
# 최소 대기 시간만으로 한도를 소진하는 계획은 실행 전에 거부한다. 응답 지연은 실행 중 감시한다.
(((candidates - 1) * interval < max_runtime)) || fail_usage '요청 간격이 전체 실행 한도를 소진합니다'

# 전체 URL을 앵커로 검증해 사용자 정보, 쿼리, fragment, 경로, 셸 메타문자와 모호한 포트를 거부한다.
[[ ${#url} -le 128 && $url =~ ^(http|https)://(127\.0\.0\.1|\[::1\])(:([1-9][0-9]{0,4}))?/?$ ]] || fail_usage '숫자형 loopback URL만 허용합니다'
scheme=${BASH_REMATCH[1]} host=${BASH_REMATCH[2]} port=${BASH_REMATCH[4]:-}
if [[ -n $port ]]; then
  bounded_number "$port" 1 65535 || fail_usage '포트는 1..65535입니다'
fi
origin="$scheme://$host${port:+:$port}"

if ((execute == 0)); then
  printf 'dry-run: tool=%s target=%s candidates=%s concurrency=%s timeout=%ss; 실제 요청 0건\n' \
    "$tool" "$origin" "$candidates" "$concurrency" "$request_timeout"
  printf 'interval=%ss max-runtime=%ss; 순서대로 요청하며 실제 응답과 탐지는 미확정\n' "$interval" "$max_runtime"
  printf 'path=/%s\n' "${REQUEST_PATHS[@]}"
  exit 0
fi

# 기존 증거는 noclobber로 보존한다. 새 파일은 이 실행의 소유로 표시하고 종료 트랩에서만 기록한다.
if [[ -z $evidence ]]; then
  evidence="web-dir-scan-$(date -u +%Y%m%dT%H%M%SZ)-$$.txt"
fi
[[ -n $evidence && $evidence != *$'\n'* && $evidence != *$'\r'* ]] || fail_usage '증거 경로가 올바르지 않습니다'
if ! (set -C; : > "$evidence") 2>/dev/null; then
  fail_usage '증거 파일이 이미 있거나 생성할 수 없습니다'
fi

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
state=tool_error attempted=0 observed=0
status_200=0 status_301=0 status_302=0 status_403=0 status_404=0 status_other=0
child_pid='' temp_dir=''

# 전체 실행 시계는 date로 읽어 테스트에서 가상 시계를 주입할 수 있다. 잘못된 시계는 실패로 닫는다.
clock_now() {
  now=$(date +%s) || { state=tool_error; exit 70; }
  [[ $now =~ ^[0-9]{1,12}$ ]] || { state=tool_error; exit 70; }
}

check_deadline() {
  clock_now
  if ((now >= deadline)); then state=timeout; exit 124; fi
}

wait_owned() {
  while kill -0 "$child_pid" 2>/dev/null; do
    check_deadline
    sleep 0.1 || { state=tool_error; exit 70; }
  done
  if wait "$child_pid"; then rc=0; else rc=$?; fi
  child_pid=''
}

record_status() {
  case $1 in
    200) ((status_200 += 1)) ;;
    301) ((status_301 += 1)) ;;
    302) ((status_302 += 1)) ;;
    403) ((status_403 += 1)) ;;
    404) ((status_404 += 1)) ;;
    *) ((status_other += 1)) ;;
  esac
  ((observed += 1))
}

collect_gobuster_statuses() {
  local line path status i
  [[ $tool == gobuster && -n $temp_dir && -f $temp_dir/output ]] || return 0
  # 완료·중단 모두 종료 트랩에서 한 번만 집계한다. 필터 밖 404나 진단 문구는 관측 응답이 아니다.
  # 합성 후보의 결과 행만 허용하며 최대 20개 후보와 4종 상태로 비교량을 제한한다.
  while IFS= read -r line; do
    if [[ $line =~ ^/([a-zA-Z0-9.]+)[[:space:]]+\(Status:[[:space:]]*(200|301|302|403)\) ]]; then
      path=${BASH_REMATCH[1]} status=${BASH_REMATCH[2]}
      for ((i = 0; i < MAX_CANDIDATES; i++)); do
        if [[ $path == "${PATHS[i]}" ]]; then
          record_status "$status"
          break
        fi
      done
    fi
  done < "$temp_dir/output"
}

finish() {
  local code=$1 ended_at
  trap - EXIT INT TERM
  if [[ -n $child_pid ]] && kill -0 "$child_pid" 2>/dev/null; then
    kill -TERM "$child_pid" 2>/dev/null || true
    for ((attempt = 0; attempt < 10; attempt++)); do
      kill -0 "$child_pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$child_pid" 2>/dev/null; then
      kill -KILL "$child_pid" 2>/dev/null || true
    fi
    wait "$child_pid" 2>/dev/null || true
  fi
  collect_gobuster_statuses
  if [[ -n $temp_dir && -d $temp_dir ]]; then
    rm -f -- "$temp_dir/wordlist" "$temp_dir/output"
    rmdir -- "$temp_dir" 2>/dev/null || true
  fi
  ended_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  {
    printf 'started_at=%s\nended_at=%s\n' "$started_at" "$ended_at"
    printf 'tool=%s\ntarget=%s\nstate=%s\nexit_code=%s\n' "$tool" "$origin" "$state" "$code"
    printf 'planned_requests=%s\nattempted_requests=%s\nobserved_statuses=%s\n' \
      "$candidates" "$attempted" "$observed"
    printf 'http_200=%s\nhttp_301=%s\nhttp_302=%s\nhttp_403=%s\nhttp_404=%s\nhttp_other=%s\n' \
      "$status_200" "$status_301" "$status_302" "$status_403" "$status_404" "$status_other"
  } >> "$evidence"
  printf 'state=%s exit_code=%s evidence=%s\n' "$state" "$code" "$evidence" >&2
}
trap 'finish $?' EXIT
trap 'state=interrupted; exit 130' INT
trap 'state=interrupted; exit 143' TERM

# 도구 부재는 실행 전 기록한다. 외부 도구의 설정 파일과 프록시 환경에 의한 우회도 차단한다.
if ! command -v "$tool" >/dev/null 2>&1; then
  state=tool_missing
  exit 127
fi
export HTTP_PROXY='' HTTPS_PROXY='' ALL_PROXY='' http_proxy='' https_proxy='' all_proxy='' NO_PROXY='*' no_proxy='*'
clock_now
deadline=$((now + max_runtime))

if [[ $tool == curl ]]; then
  temp_dir=$(mktemp -d) || { state=tool_error; exit 70; }
  chmod 700 "$temp_dir"
  for ((i = 0; i < candidates; i++)); do
    check_deadline
    if ((i > 0 && interval > 0)); then
      sleep "$interval" &
      child_pid=$!
      wait_owned
      ((rc == 0)) || { state=tool_error; exit "$rc"; }
      check_deadline
    fi
    ((attempted += 1))
    code=''
    curl_args=(-q --silent --noproxy '*' --proxy '' --max-redirs 0 --proto '=http,https'
      --connect-timeout "$request_timeout" --max-time "$request_timeout"
      --output /dev/null --write-out '%{http_code}' -- "$origin/${REQUEST_PATHS[i]}")
    # 소유 PID를 추적해야 중단·전체 시간 초과 시 curl도 회수할 수 있다. 원시 출력은 증거에 복사하지 않는다.
    curl "${curl_args[@]}" > "$temp_dir/output" 2>/dev/null &
    child_pid=$!
    wait_owned
    if ((rc == 0)); then
      code=$(< "$temp_dir/output")
      [[ $code != 000 ]] || { state=connection_failure; exit 7; }
      [[ $code =~ ^[1-5][0-9][0-9]$ ]] || { state=tool_error; exit 70; }
      record_status "$code"
      check_deadline
    else
      case $rc in
        28) state=timeout; exit 124 ;;
        6|7) state=connection_failure; exit "$rc" ;;
        130|143) state=interrupted; exit "$rc" ;;
        *) state=tool_error; exit "$rc" ;;
      esac
    fi
  done
else
  temp_dir=$(mktemp -d) || { state=tool_error; exit 70; }
  chmod 700 "$temp_dir"
  printf '%s\n' "${PATHS[@]:0:candidates}" > "$temp_dir/wordlist"
  # gobuster는 기본 404 블랙리스트와 -s를 함께 허용하지 않으며, 404를 양성 목록에 넣으면 사전 wildcard 검사가 실패한다.
  gobuster_args=(dir -q --no-color --no-progress --no-error -u "$origin" -w "$temp_dir/wordlist"
    -t "$concurrency" --timeout "${request_timeout}s" -b '' -s '200,301,302,403')
  gobuster "${gobuster_args[@]}" > "$temp_dir/output" 2>/dev/null &
  child_pid=$!
  attempted=unknown
  # gobuster의 개별 요청 제한에 더해 전체 실행에도 상한을 둔다.
  clock_now
  tool_deadline=$((now + candidates * request_timeout + 5))
  ((tool_deadline >= deadline)) || deadline=$tool_deadline
  while kill -0 "$child_pid" 2>/dev/null; do
    check_deadline
    sleep 0.1 || { state=tool_error; exit 70; }
  done
  if wait "$child_pid"; then rc=0; else rc=$?; fi
  child_pid=''
  if ((rc != 0)); then
    case $rc in
      28|124) state=timeout; exit 124 ;;
      130|143) state=interrupted; exit "$rc" ;;
      1|6|7) state=connection_failure; exit "$rc" ;;
      *) state=tool_error; exit "$rc" ;;
    esac
  fi
fi
state=completed
