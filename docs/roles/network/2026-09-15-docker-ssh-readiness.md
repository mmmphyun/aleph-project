# Docker SSH 실측 준비 상태 — 실측 보고서 아님

- 확인 일자: 2026-09-15, Asia/Seoul (UTC+09:00)
- 기반 main: `c7efad2`
- 환경 준비: https://github.com/mmmphyun/aleph-project/issues/54
- 원본 실측 대기: https://github.com/mmmphyun/aleph-project/issues/28
- 원본 노션: https://notion.so/3d404d37c22581bb995bf25b914b8abe

## 확인 결과

| 항목 | 확인한 사실 |
| --- | --- |
| OS | Microsoft Windows 11 Pro, 10.0.26200 |
| Docker | CLI PATH, 표준 Program Files/사용자 설치 경로, 서비스에서 발견되지 않음. 이미지 빌드·엔진·Linux 컨테이너 실측 불가 |
| WSL | `wsl --status`가 WSL 미설치 안내 반환 |
| 가상화 | Win32_Processor의 VirtualizationFirmwareEnabled / SecondLevelAddressTranslationExtensions 모두 False. 실제 BIOS/상위 VM 지원 여부 미확정 |
| Windows 선택 기능 | VirtualMachinePlatform 및 WSL 상세 조회는 관리자 권한 필요로 확인하지 못함 |
| 여유 공간 | 조회 시 425,541,484,544 bytes, 약 396GiB. 이미지 다운로드 크기는 미확정 |
| Bash | `C:\Program Files\Git\bin\bash.exe` 존재 |
| tshark | `C:\Program Files\Wireshark\tshark.exe`, 4.6.8, v4.6.8-0-ge677bf052328 |
| Wireshark GUI | 직접 확인하지 않음 |
| 이미지 / tcpdump 버전 | 빌드·실행 미수행으로 미확정 |

설치/기능 활성화/재부팅은 수행하지 않았다. Docker 설정의 Linux 실행 가능성·최소 capability·
키 인증·캡처 FD 기록은 모의 테스트만으로 확인할 수 없으며 후속 실측이 필요하다.

## 실제 관측 결과

실제 SSH 연결·tcpdump 캡처·tshark 분석은 미수행이다. pcap 위치/크기/해시/읽기 결과,
실험 시작·종료 시각, 실제 IP·인터페이스·4-tuple·프레임 번호는 없다.

| 구간 | 상대 시각 / 방향 / TCP 플래그 / Seq·Ack | 결론 |
| --- | --- | --- |
| 연결 수립 | 미관측 | SYN → SYN/ACK → ACK 실측 미완료 |
| 종료 | 미관측 | FIN/RST 유무를 판단하지 않음 |
| 재전송·공격 패턴 | 미관측 | 정상/이상 판정 불가 |

위 표는 상태 설명이며 패킷 타임라인이 아니다. 가짜 테스트 출력·합성 패킷을 증거로 사용하지 않는다.
초안 `e7cbdeb`에서는 프레임 근거·시간 기준·사실/해석 분리 원칙만 참고했다.
초안 전체를 병합하거나 기존 초안 파일을 완성 보고서로 변경하지 않았다.

## 후속 실측과 해석 범위

1. 가상화 지원·WSL2·Docker Desktop Linux 엔진 준비 후 사용 문서의 build/run을 명시적으로 실행한다.
2. 캡처 준비 확인, SSH 및 tcpdump 종료 코드, stderr 드롭 통계와 실제 pcap 읽기를 확인한다.
3. pcap SHA-256, 도구/이미지 버전, 명령/필터, 실제 IP·포트·인터페이스와 시간대를 기록한다.
4. 단일 스트림의 4-tuple·프레임·SYN 기준 상대 시각·방향·플래그·Seq/Ack 표를 실측값으로 작성한다.
5. 관측된 FIN/RST/재전송과 가능한 원인을 구분한다. 인증 결과는 SSH 종료 코드와 서버 로그로 확인한다.
6. 정상 연결의 시도 수·연결 수립 간격·종료 형태를 향후 승인된 Hydra 비교 기준으로 보존한다.
   이번 작업에서는 Hydra/Nmap·외부 서버 접속을 실행하지 않는다.

컨테이너 간 동일 내부 bridge 경로는 외부 서비스 접속 경로와 다르다. Docker Desktop의 Linux
가상화·스케줄링·가상 NIC·오프로딩이 관측 시각/체크섬 등에 영향을 줄 수 있다.
동일 bridge 통신의 결과를 외부 NAT를 통과한 결과로 가정하지 않으며,
EC2/GCP 지연·보안 그룹·WAF·외부 방화벽 동작이나 CloudShield 10초 대응으로 일반화하지 않는다.
SSH 암호화 이후 패킷에서 비밀번호·인증 상세 내용을 읽었다고 주장하지 않는다.

## 기존 작업과 자동화

- 시작 작업 트리: `feat/network-tcpdump-capture`, 미커밋 변경 없음.
- 네트워크 열린 PR 없음 확인 후 main을 `git pull --ff-only origin main`으로 갱신했다.
- SSH PR 30: MERGED, `c54ed793eeedbaf3132824011687432240f34953`.
- tcpdump PR 35: MERGED, `b81aa3298aa8cea188dff444823b7a1f334b7928`.
  관련 이슈 29·34는 CLOSED이며 완료 범위는 구현/모의 검증이다.
- 보고서 이슈 28은 PR 30 자동화로 오종료된 뒤 9월 11일 재개됐다가
  06:16:57 UTC에 테크 리드 `mmmphyun`이 다시 닫았다. 본문·노션은 실제 캡처 대기를 명시한다.
  이번 준비 작업에서는 임의 재개하거나 완료로 취급하지 않았다.
- `feat/network-syn-ack-analysis`와 `e7cbdeb`, 보관 `feat/network-ssh-bruteforce` 및 PR 15는 보존한다.
- 원본 노션은 조회 시 `진행 중`, 원본 제목 유지, PR/Commit 없음이었다.
- 환경 준비 이슈는 별도 노션 카드를 GitHub Actions가 생성했다.
  원본 카드의 상태·속성을 에이전트가 직접 수정하지 않는다.
- 최신 자동화: 이슈 opened/reopened → 진행 중·시작일 설정; PR opened/reopened → 검토 중;
  merged → 완료·종료일·커밋 설정. 기존 `[직무]` 제목은 보존한다.
- PR 본문의 첫 노션 링크가 자동화 대상이므로 환경 준비 카드를 먼저 기재한다.
  머지 시 본문의 모든 `#숫자` 이슈를 닫는 동작이 남아 있어 원본 이슈는 전체 URL로만 참조한다.
  환경 준비 PR은 자동 머지하지 않는다.

## 이번 검증과 로컬 산출물

- `powershell .\scripts\check.ps1`: 표준 경로 검사·Ruff lint 통과,
  Ruff format 68 files already formatted, pytest **187 passed / 2 skipped / 1 warning** (18.47초).
- 네트워크 **106 passed**: 기존 SSH/tcpdump 91개 유지 + Docker 러너 모의 검증 15개.
- 기존 skip은 remediation/reporter 각 1개, 기존 warning은 test_smoke의 pytest-socket DNS 차단 경고다.
  신규 테스트 skip·경고 없음.
- 최초 샌드박스 테스트는 임시 폴더 권한 오류로 실패했다. 작업 폴더 임시 경로의 모의 테스트는 통과했고
  이 임시 파일들은 제거했다. 최종 게이트는 사용자 환경의 기존 CurrentUser RemoteSigned 정책으로
  실행했으며 실행 정책 변경·우회 플래그·검증 코드 수정은 하지 않았다.
- 게이트 로그: `C:\Aleph\network\lab\runs\check-user.log` (Git 제외).
- 실측 실행 진입 확인: `python network/lab/run.py run`은 Docker CLI 부재로 코드 1 반환.
  사전 점검에서 종료되어 실제 SSH/캡처·이미지 다운로드 없음.
- 해당 로그: `C:\Aleph\network\lab\runs\20260915T072403Z-63475706\manifest.json`
  (2026-09-15 07:24:03 UTC / 16:24:03 KST, Git 제외).
- 생성한 컨테이너·네트워크·이미지·임시 인증 키 없음. pcap 없음.
  남은 로컬 산출물은 환경 오류 manifest와 검증 로그뿐이며 정리할 Docker 자원은 없다.
