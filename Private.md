## OWASP Top 10별 정적 분석 탐지 가능성
### 정적 분석으로 비교적 잘 탐지되는 항목

- A03 (Injection): 50-70% 정도 - 기본적인 패턴은 탐지 가능
- A06 (Vulnerable Components): 80-90% - 의존성 파일 분석으로 잘 탐지됨
- A07 (Authentication Failures): 30-50% - 하드코딩된 크리덴셜은 탐지 가능

### 정적 분석으로 탐지 어려운 항목

- A01 (Broken Access Control): 10-20% - 비즈니스 로직과 런타임 권한 체크 필요
- A02 (Cryptographic Failures): 30-40% - 설정과 구현 방식에 따라 다름
- A04 (Insecure Design): 5-10% - 아키텍처와 설계 결함이라 코드로는 판단 어려움
- A05 (Security Misconfiguration): 20-30% - 서버/인프라 설정이 주요 원인
- A08 (Software/Data Integrity): 15-25% - 공급망과 런타임 검증 문제
- A09 (Logging/Monitoring Failures): 10-20% - 로그 정책과 모니터링 시스템 문제
- A10 (Server-Side Request Forgery): 40-60% - URL 구성 패턴은 일부 탐지 가능

## 왜 정적 분석만으론 부족한가?
### 1. 런타임 의존적 취약점
```python
# A01 - Broken Access Control 예시
@login_required
def view_user_data(request, user_id):
    # 정적 분석으로는 이 함수가 안전해 보임
    user = User.objects.get(id=user_id)
    return render(request, 'user.html', {'user': user})

# 하지만 실제로는 다른 사용자의 데이터도 볼 수 있는 취약점
# 이건 비즈니스 로직 검증이 필요함 (현재 사용자 != user_id 소유자)
```
### 2. 설정과 환경 의존적
```yaml
# A05 - Security Misconfiguration
# nginx.conf - 정적 분석 범위 밖
server {
    server_tokens on;  # 버전 정보 노출
    add_header X-Frame-Options "ALLOWALL";  # 클릭재킹 취약
}
```
### 3. 아키텍처 설계 문제
```python
# A04 - Insecure Design
# 코드 자체는 문제없어 보이지만...
def transfer_money(from_account, to_account, amount):
    if from_account.balance >= amount:
        from_account.balance -= amount
        to_account.balance += amount
        
# 문제: 동시성 제어 없음, 트랜잭션 없음 등
# 이런 설계 결함은 정적 분석으로 찾기 어려움
```

## 현실적인 접근 방법
### 우리가 구현하려는 3개 항목이 합리적인 이유:

- A03, A06, A07은 정적 분석으로 상당히 효과적으로 탐지 가능
- 나머지 항목들은 DAST, 수동 테스트, 코드 리뷰 등이 더 효과적

### 전체적인 보안 접근법:

- 정적 분석 (SAST): A03, A06, A07 위주
- 동적 분석 (DAST): A01, A05, A10 위주
- 수동 테스트: A04, A08, A09 위주
- 의존성 스캔: A06 특화
- 인프라 스캔: A02, A05 특화