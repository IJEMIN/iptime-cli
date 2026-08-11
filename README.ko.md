# iptime-cli

Flutter/Canvas로 렌더링되는 ipTIME 관리 페이지를 DOM 자동화하지 않고,
공유기 웹 UI가 사용하는 로컬 HTTP RPC를 직접 호출하는 macOS CLI입니다.
공유기 펌웨어는 수정하지 않습니다.

> [!WARNING]
> EFM Networks 또는 ipTIME의 공식 프로젝트가 아닌 실험적 상호운용 도구입니다.
> 비공개 RPC는 펌웨어 업데이트로 바뀔 수 있습니다. 본인이 소유하거나 관리 권한이
> 있는 공유기에서만 사용하세요.

[English](README.md)

## 주요 기능

- 제품·네트워크 상태, 연결 단말, DHCP, Wi-Fi, 포트포워딩 조회
- 스크립트와 AI 에이전트가 사용하기 쉬운 JSON 출력
- 출력 내 비밀번호·토큰 기본 마스킹
- macOS Keychain 및 숨김 비밀번호 입력
- 세션 쿠키를 디스크에 저장하지 않음
- `0600` 권한의 설정 백업
- Wi-Fi와 포트포워딩 변경은 기본 dry-run, `--yes`가 있어야 적용
- 위험도 분류가 적용된 저수준 RPC 호출

현재 베타 단계이며 모델·펌웨어에 따라 호환성이 다를 수 있습니다.

## 설치

macOS와 Go 1.25 이상이 필요합니다.

```sh
git clone https://github.com/IJEMIN/iptime-cli.git
cd iptime-cli
go build -o ./bin/iptime ./cmd/iptime
install -m 0755 ./bin/iptime /usr/local/bin/iptime
```

## 시작하기

전역 옵션은 명령 앞에 둡니다.

```sh
iptime --router http://192.168.0.1 probe
iptime --router http://192.168.0.1 credential set
iptime --router http://192.168.0.1 status
iptime --router http://192.168.0.1 clients
iptime --router http://192.168.0.1 dhcp
iptime --router http://192.168.0.1 wifi show
iptime --router http://192.168.0.1 port-forward list
```

기본 주소는 `http://192.168.0.1`, 기본 계정명은 `admin`입니다. 비밀번호는
명령 인자나 환경변수로 받지 않습니다. Wi-Fi와 유선이 같은 서브넷에 동시에
연결되어 있다면 인터페이스를 지정합니다.

```sh
iptime --interface <interface-name> status
```

## 설정 변경

아래 첫 명령은 계획만 출력하고, 두 번째 명령만 실제로 적용합니다.

```sh
iptime wifi set --bss <bss-id> --ssid ExampleWiFi
iptime wifi set --bss <bss-id> --ssid ExampleWiFi --yes
```

실제 변경 직전에는 전체 설정을
`~/Library/Application Support/iptime-cli/backups/<router-id>/`에 `0600` 권한으로
자동 백업합니다. 주소를 노출하지 않는 공유기별 ID로 여러 공유기의 백업을
분리합니다. 백업에는 자격증명이 포함될 수 있고 자동 삭제되지 않으므로 로컬에서
주기적으로 정리하세요. 디코딩 가능하고 최소 크기를 충족하는 백업을 만들지 못하면
변경도 중단됩니다. 이 검사는 펌웨어별 백업의 실제 복구 가능성까지 보장하지
않습니다. 별도 복구 수단이 확실한 경우에만 `--no-backup`으로 생략할 수 있습니다.

```sh
iptime port-forward add \
  --name example-web \
  --target 192.168.0.10 \
  --external-port 8443 \
  --internal-port 443
```

설정 백업에는 관리자·Wi-Fi 자격증명이 포함될 수 있습니다.

```sh
iptime backup --output "$HOME/Desktop/router-backup.config"
```

## 개인정보 보호 경계

- 텔레메트리, 클라우드 전송, 백그라운드 서비스 없음
- 비밀번호는 Keychain·숨김 프롬프트·명시적 stdin 입력만 사용
- 세션은 메모리에만 유지하고 작업 후 로그아웃
- 일반 출력에는 관리에 필요한 내부 IP, MAC, SSID, 단말명이 포함될 수 있음
- 공개 이슈에는 원문 출력, 설정 백업, 관리자 화면, HAR/PCAP을 첨부하지 말 것
- 공유용 진단에는 `iptime doctor`만 사용할 것

많은 공유기의 기본 관리 페이지는 평문 HTTP를 사용하므로 Keychain을 쓰더라도
로그인 비밀번호가 로컬 네트워크 구간에서는 암호화되지 않을 수 있습니다. 신뢰할
수 있는 LAN에서 사용하고, 공유기에 HTTPS를 구성했다면 HTTPS 주소를 사용하세요.
`--insecure`는 HTTPS 인증서 검증을 끄므로, 신뢰할 수 있는 LAN에서 공유기 주소와
인증서 상황을 별도로 확인한 경우에만 사용하세요.

자세한 사용법과 안전 모델은 [영문 README](README.md), 프로토콜 구조는
[docs/protocol.md](docs/protocol.md)를 참고하세요.
