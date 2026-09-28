# Web 디렉터리 모의 스캔 실행 가이드

이 실험은 합성 경로를 짧은 시간에 요청해 HTTP 경로, 상태 코드, 요청 빈도에 남는 L7 흔적을 확인하기 위한 것이다. TCP 플래그 기반 SG 분석이나 실제 WAF 차단 실험은 포함하지 않는다.

## 준비와 dry-run

Git Bash에서 저장소 루트 기준으로 실행한다. 기본값은 `curl`, 후보 10개, 동시성 1, 요청당 제한 시간 3초이며 요청을 보내지 않는다.

```bash
bash network/web_dir_scan.sh --url http://127.0.0.1:8080
bash network/web_dir_scan.sh --url http://127.0.0.1:8080 --tool gobuster --candidates 10 --concurrency 2 --timeout 3
```

## 명시적 실행

로컬에서 직접 관리하는 테스트 HTTP 서버를 준비하고, 대상 포트가 의도한 서비스인지 확인한다. 실제 요청은 `--execute`가 있어야 시작된다. 숫자형 `127.0.0.1` 또는 `[::1]`만 허용하며 DNS 이름, 외부 주소, URL 사용자 정보, 쿼리, fragment, 추가 경로는 거부한다. 프록시는 비활성화한다. Docker 대상이나 별도 승인 테스트 대상은 현재 스크립트가 직접 소유·검증할 수 없으므로 지원하지 않는다.

```bash
bash network/web_dir_scan.sh --url http://127.0.0.1:8080 --candidates 5 --timeout 2 --evidence ./web-dir-evidence.txt --execute
bash network/web_dir_scan.sh --url http://127.0.0.1:8080 --tool gobuster --candidates 5 --concurrency 2 --timeout 2 --evidence ./gobuster-evidence.txt --execute
```

후보는 스크립트 내 합성 경로 20개로 고정한다. 후보 수는 1~20, gobuster 동시성은 1~4, curl 동시성은 1, 요청 제한 시간은 1~10초다. 리다이렉트를 따라가지 않으며 인증 정보나 응답 본문을 저장하지 않는다.

## 중단·증거·정리

터미널에서 `Ctrl+C`로 중단한다. 스크립트가 생성한 gobuster 프로세스와 임시 wordlist만 정리하며 다른 프로세스나 파일은 건드리지 않는다. 중단, 요청 timeout, 도구 부재, 연결 실패는 증거 파일의 `state`와 `exit_code`로 구분한다.

증거는 `--evidence`로 지정한 경로에 새로 생성된다. 생략하면 현재 디렉터리에 `web-dir-scan-<UTC 시각>-<PID>.txt`가 생성된다. 기존 파일은 덮어쓰지 않는다. 시작·종료 UTC 시각, 계획·시도 요청 수, 관측 상태 수, HTTP 200/301/302/403/404/기타 분포를 기록한다. curl은 각 요청의 실제 시도 수와 상태 코드를 집계한다. gobuster는 내부 사전 검사 요청과 필터링 때문에 실제 시도 수를 확정할 수 없어 `attempted_requests=unknown`으로 표시하며, 404는 wildcard 사전 검사와 충돌하므로 결과에서 제외한다. 404 분포가 필요하면 curl 모드를 사용한다. 필요한 증거만 검토·보관하고, 실험 종료 후 본인이 만든 증거 파일을 직접 삭제한다.

SG conntrack 동작 분석과 WAF 403 이후 FIN/RST 패킷 분석 및 PCAP 보고서는 각 전용 후속 티켓에서 다룬다. 이 가이드로 실제 SG 교체나 WAF 차단을 수행하지 않는다.
