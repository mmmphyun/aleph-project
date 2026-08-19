# CloudTrail 샘플 Fixture

이 폴더에는 파서와 탐지 규칙 테스트에 사용하는 비식별화된 CloudTrail JSON을 저장합니다.

필수 샘플:

- `assume_role.json`
- `put_bucket_acl.json`
- `authorize_security_group_ingress.json`

실제 계정 ID, ARN, IP, 사용자명, Access Key, Session Token을 저장하지 않습니다. AWS 공식 예시 또는 테스트 계정에서 생성한 로그를 테스트용 값으로 치환한 뒤 추가합니다.
