#!/usr/bin/env python3
"""
JavaScript 인증 취약점 테스트 샘플
A07 Authentication에 추가된 JavaScript 패턴들을 테스트
"""

import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import OWASPStaticAnalyzer


def create_js_auth_test():
    scanner = OWASPStaticAnalyzer()
    
    test_project = {
        "project_id": "js_auth_test",
        "source_files": [
            {
                "path": "/auth/jwt-service.js",
                "language": "javascript",
                "content": '''
// JWT 보안 취약점들
const jwt = require('jsonwebtoken');

class JWTService {
    // 약한 JWT 시크릿
    generateToken(payload) {
        return jwt.sign(payload, "secret123");  // 너무 짧은 시크릿
    }
    
    generateWeakToken(data) {
        return jwt.sign(data, "test");  // 매우 약한 시크릿
    }
    
    // 하드코딩된 API 키들
    setupAPI() {
        const apiKey = "sk-1234567890abcdef1234567890abcdef";
        const bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        const accessToken = "access_1234567890abcdef";
        const clientSecret = "client_secret_abcdef123456";
        
        return { apiKey, bearer, accessToken, clientSecret };
    }
}

// 패스워드 보안 문제들
class AuthService {
    // 약한 기본 패스워드
    setupDefaultUser() {
        const password = "password";
        const adminPass = "admin";
        const testPass = "123";
        
        return { password, adminPass, testPass };
    }
    
    // 약한 해싱
    hashPassword(password) {
        const crypto = require('crypto');
        return crypto.createHash('md5').update(password).digest('hex');
    }
    
    hashPasswordSHA1(password) {
        return crypto.createHash('sha1').update(password).digest('hex');
    }
    
    // 브라우저 저장소에 패스워드 저장
    storePassword(password) {
        localStorage.setItem('userPassword', password);
        sessionStorage.setItem('tempPassword', password);
    }
    
    // Base64는 암호화가 아님
    encodePassword(password) {
        return btoa(password + "salt");
    }
}

// 세션 관리 문제들
const express = require('express');
const session = require('express-session');

const app = express();

// 안전하지 않은 세션 설정
app.use(session({
    secret: 'session-secret',
    secure: false,         // HTTPS에서만 전송되지 않음
    httpOnly: false,       // XSS로 접근 가능
    maxAge: 1000          // 너무 짧은 세션 타임아웃
}));

// 쿠키 조작
function setCookie(name, value) {
    document.cookie = name + "=" + value + "; path=/";
}

// OAuth 보안 문제들
class OAuthService {
    constructor() {
        this.clientSecret = "oauth_client_secret_12345";  // 하드코딩된 클라이언트 시크릿
        this.redirectUri = "http://localhost:3000/callback";  // 하드코딩된 리다이렉트 URI
    }
    
    initiateOAuth() {
        const state = "static";  // 약한 state 파라미터
        const fixedState = "123";
        
        return { state, fixedState };
    }
}

// 암호화 오용
class CryptoService {
    // 약한 해시 알고리즘
    createWeakHash(data) {
        const crypto = require('crypto');
        return crypto.createHash('md5').update(data).digest('hex');
    }
    
    // 클라이언트 사이드 약한 해싱
    clientSideHash(data) {
        const CryptoJS = require('crypto-js');
        return CryptoJS.MD5(data).toString();
    }
    
    generateWeakSecret() {
        const secret = Math.random() * 1000000;  // 약한 랜덤 생성
        const timeSecret = Date.now() + "secret";  // 예측 가능한 시크릿
        
        return { secret, timeSecret };
    }
}

// 인증 우회
class AdminService {
    // 하드코딩된 인증 우회
    checkAuth(user) {
        if (true) {  // 항상 true인 인증
            return { authenticated: true };
        }
    }
    
    setupAdmin() {
        const auth = true;  // 하드코딩된 인증
        const isAdmin = true;  // 하드코딩된 권한 상승
        const authenticated = true;
        
        return { auth, isAdmin, authenticated };
    }
}

// CORS 잘못된 설정
const cors = require('cors');

app.use(cors({
    origin: true,  // 모든 오리진 허용
    credentials: true
}));

// 안전하지 않은 CORS 헤더
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');  // 와일드카드 오리진
    next();
});
'''
            },
            {
                "path": "/config/security.ts",
                "language": "typescript",
                "content": '''
// TypeScript 인증 보안 문제들
interface AuthConfig {
    jwtSecret: string;
    apiKey: string;
    sessionSecret: string;
}

class SecurityConfig {
    private config: AuthConfig = {
        jwtSecret: "typescript_secret_123",  // 약한 JWT 시크릿
        apiKey: "ts-api-key-1234567890abcdef",  // 하드코딩된 API 키
        sessionSecret: "session-secret-ts"   // 약한 세션 시크릿
    };
    
    // OAuth 설정
    private oauthConfig = {
        clientSecret: "oauth_ts_secret_123456",  // 클라이언트 시크릿 노출
        redirectUri: "https://myapp.com/oauth/callback",
        state: "fixed"  // 고정된 state
    };
    
    // 암호화 설정
    hashPassword(password: string): string {
        const crypto = require('crypto');
        return crypto.createHash('md5').update(password).digest('hex');  // 약한 해싱
    }
    
    generateToken(payload: any): string {
        const jwt = require('jsonwebtoken');
        return jwt.sign(payload, "dev");  // 매우 약한 시크릿
    }
    
    // 인증 우회
    authenticateUser(credentials: any): boolean {
        const isAuth = true;  // 하드코딩된 인증
        return isAuth;
    }
}

// Express 보안 설정
import express from 'express';
import session from 'express-session';

const app = express();

app.use(session({
    secret: 'ts-session',
    secure: false,    // HTTPS 전용이 아님
    httpOnly: false,  // XSS 공격 가능
    maxAge: 900      // 15분으로 매우 짧음
}));

// CORS 설정 문제
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');  // 모든 도메인 허용
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});
'''
            }
        ],
        "dependency_files": [
            {
                "type": "package.json",
                "content": '''
{
  "dependencies": {
    "jsonwebtoken": "8.5.0",
    "express-session": "1.16.0",
    "passport": "0.4.1",
    "cors": "2.8.5",
    "helmet": "4.6.0",
    "bcrypt": "5.0.0"
  }
}
'''
            }
        ]
    }
    
    return scanner.analyze_project(test_project)


def print_auth_results(result):
    print("=" * 80)
    print("🔐 JavaScript 인증 취약점 스캐너 테스트 결과")
    print("=" * 80)
    
    summary = result['summary']
    print(f"총 발견된 취약점: {summary['total_vulnerabilities']}개")
    print(f"🔴 Critical: {summary['critical']}")
    print(f"🟠 High: {summary['high']}")
    print(f"🟡 Medium: {summary['medium']}")
    print(f"🟢 Low: {summary['low']}")
    print()
    
    # A07 인증 관련 취약점만 필터링
    auth_vulns = [v for v in result['vulnerabilities'] if v['owasp_category'] == 'A07']
    
    # 인증 취약점 타입별 분류
    auth_types = {}
    for vuln in auth_vulns:
        vuln_type = vuln['type']
        if vuln_type not in auth_types:
            auth_types[vuln_type] = 0
        auth_types[vuln_type] += 1
    
    print("🔐 A07 인증 취약점 타입별 분류:")
    print("-" * 50)
    for vuln_type, count in sorted(auth_types.items()):
        print(f"  {vuln_type}: {count}개")
    print()
    
    print("🚨 발견된 주요 인증 취약점들:")
    print("-" * 60)
    
    # 심각도별로 정렬
    sorted_auth_vulns = sorted(auth_vulns, 
                              key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[x['severity']], 
                              reverse=True)
    
    for i, vuln in enumerate(sorted_auth_vulns[:20], 1):  # 상위 20개 표시
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        print(f"{i:2d}. {severity_emoji[vuln['severity']]} {vuln['type'].upper()}")
        print(f"    파일: {vuln['file_path']}:{vuln['line_number']}")
        print(f"    설명: {vuln['description']}")
        print(f"    신뢰도: {vuln['confidence']:.2f}")
        print(f"    권장사항: {vuln['recommendation'][:80]}...")
        print(f"    코드: {vuln['code_snippet'][:70]}...")
        print()
    
    print("🛡️ JavaScript 인증 보안 가이드라인:")
    print("-" * 60)
    guidelines = [
        "1. JWT 시크릿: 32자 이상의 강력한 무작위 문자열 사용",
        "2. API 키: 환경변수나 보안 저장소에 보관",
        "3. 패스워드: bcrypt/scrypt 사용, 브라우저 저장 금지",
        "4. 세션: secure, httpOnly 플래그 설정",
        "5. OAuth: 클라이언트 시크릿 노출 금지, 동적 state 사용",
        "6. 암호화: MD5/SHA1 사용 금지, 강력한 해시 알고리즘 사용",
        "7. 인증: 하드코딩된 우회 로직 제거",
        "8. CORS: 와일드카드(*) 사용 금지, 명시적 도메인 설정"
    ]
    
    for guideline in guidelines:
        print(f"  {guideline}")
    print()
    
    # 보안 등급 평가
    critical_count = len([v for v in auth_vulns if v['severity'] == 'CRITICAL'])
    high_count = len([v for v in auth_vulns if v['severity'] == 'HIGH'])
    
    if critical_count > 0:
        grade = "🔴 위험 (Critical)"
        advice = "즉시 수정이 필요한 치명적 보안 취약점이 발견되었습니다."
    elif high_count > 5:
        grade = "🟠 경고 (High Risk)"
        advice = "높은 우선순위로 수정이 필요한 보안 취약점들이 있습니다."
    elif high_count > 0:
        grade = "🟡 주의 (Medium Risk)"
        advice = "몇 가지 보안 취약점이 발견되었습니다. 검토 후 수정하세요."
    else:
        grade = "🟢 양호 (Low Risk)"
        advice = "주요 인증 취약점이 발견되지 않았습니다."
    
    print(f"📊 보안 등급: {grade}")
    print(f"💡 권장사항: {advice}")


if __name__ == "__main__":
    print("JavaScript 인증 취약점 스캐너 테스트를 시작합니다...")
    print()
    
    try:
        result = create_js_auth_test()
        print_auth_results(result)
        
        # JSON 결과 저장
        with open('js_auth_test_result.json', 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        print("\n결과가 js_auth_test_result.json 파일에 저장되었습니다.")
        
    except Exception as e:
        print(f"❌ 테스트 중 오류 발생: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)