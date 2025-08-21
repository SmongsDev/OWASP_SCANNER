#!/usr/bin/env python3
"""
JavaScript/TypeScript 취약점 테스트 샘플
새로 추가된 JavaScript 패턴들을 테스트하는 예제
"""

import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import OWASPStaticAnalyzer


def create_js_test():
    scanner = OWASPStaticAnalyzer()
    
    # JavaScript 취약점 테스트용 프로젝트 데이터
    test_project = {
        "project_id": "js_vulnerability_test",
        "source_files": [
            {
                "path": "/frontend/app.js",
                "language": "javascript",
                "content": '''
// XSS 취약점들
function updateProfile(userData) {
    // DOM XSS
    document.getElementById('profile').innerHTML = userData.name + " Profile";
    element.outerHTML = `<div>${userData.bio}</div>`;
    
    // jQuery XSS
    $('#user-info').html(userData.description + " details");
    $('#content').append(userInput + " more data");
    
    // React-style XSS
    const dangerousHTML = { __html: userData.content + " extra" };
    
    // Event handler injection
    element.setAttribute("onclick", "alert('" + userData.script + "')");
    button.onclick = userCode + "()";
}

// Code Injection 취약점들
function processUserData(userCode) {
    // Critical vulnerabilities
    eval("var result = " + userCode);
    var func = new Function("return " + userCode);
    
    // Timing functions with code
    setTimeout("executeCode('" + userCode + "')", 1000);
    setInterval("processData('" + userInput + "')", 5000);
    
    // VM module usage
    const vm = require('vm');
    vm.runInThisContext(userCode);
    vm.runInNewContext("var x = " + userInput);
}

// Server-side injection (Node.js)
function executeCommand(userInput) {
    const { exec, execSync, spawn } = require('child_process');
    
    // Command injection
    exec('ls -la ' + userInput);
    execSync(`cat ${userInput}`);
    spawn('grep', [userPattern + ' file.txt']);
    
    // Dynamic require
    const moduleName = userInput + '-module';
    require(moduleName);
}

// SQL Injection (Node.js)
function queryDatabase(userId, tableName) {
    // Template literal injection
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    const dynamicQuery = `SELECT * FROM ${tableName} WHERE active = 1`;
    
    // ORM injection
    connection.query('SELECT * FROM posts WHERE author = ' + userName);
    sequelize.query(`UPDATE users SET status = '${userStatus}' WHERE id = ${id}`);
    knex.raw('DELETE FROM ' + tableName + ' WHERE id = ' + recordId);
    
    // Query builder injection
    User.where('name = ' + searchTerm).first();
    Post.orderBy(sortField + ' DESC').limit(10);
}

// Prototype Pollution
function mergeUserData(userData) {
    // JSON parsing
    const parsed = JSON.parse(userJsonString + '"}');
    
    // Object assignment
    Object.assign(target, userControlledObject + extraData);
    
    // Dynamic property assignment
    obj[userKey + '_prop'] = userValue;
}

// URL/SSRF vulnerabilities
function fetchUserContent(userUrl) {
    // Fetch API
    fetch('https://api.example.com/' + userPath);
    fetch(`${baseUrl}/${userEndpoint}`);
    
    // XMLHttpRequest
    const xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://external-api.com/' + userPath);
    
    // Redirect vulnerabilities
    window.location = redirectUrl + userParam;
    location.href = baseUrl + userRoute;
}

// NoSQL Injection (MongoDB)
function queryMongoDB(userId, collection) {
    // MongoDB injection
    db.collection(userCollection + '_data').find({user: userId + ''});
    User.findOne({name: userName + ' test'});
    Posts.aggregate([{$match: {category: userCategory + '_posts'}}]);
}
'''
            },
            {
                "path": "/backend/api.ts",
                "language": "typescript", 
                "content": '''
// TypeScript 취약점 예제
interface UserData {
    name: string;
    email: string;
    script?: string;
}

class DatabaseService {
    // SQL Injection in TypeScript
    async getUserById(id: string): Promise<User> {
        const query = `SELECT * FROM users WHERE id = ${id}`;
        return await this.db.query(query + ' LIMIT 1');
    }
    
    // Template literal injection
    async searchUsers(term: string, table: string): Promise<User[]> {
        return await this.db.query(`
            SELECT * FROM ${table} 
            WHERE name LIKE '%${term}%'
        `);
    }
}

class XSSService {
    // DOM manipulation
    updateUserInfo(user: UserData): void {
        document.getElementById('user-name')!.innerHTML = user.name + " (verified)";
        const container = document.querySelector('.profile')!;
        container.outerHTML = `<div class="profile">${user.name}</div>`;
    }
    
    // React-style dangerous HTML
    renderUserBio(bio: string): JSX.Element {
        return <div dangerouslySetInnerHTML={{__html: bio + " - Updated"}} />;
    }
}

// Command execution
class SystemService {
    executeUserCommand(command: string): void {
        const { exec } = require('child_process');
        exec('system-tool ' + command);
        
        // VM execution
        const vm = require('vm');
        vm.runInThisContext('const result = ' + command);
    }
}
'''
            }
        ],
        "dependency_files": [
            {
                "type": "package.json",
                "content": '''
{
  "name": "js-test-app",
  "dependencies": {
    "express": "4.16.0",
    "lodash": "4.17.15",
    "sequelize": "5.21.0",
    "mongoose": "5.9.0"
  }
}
'''
            }
        ]
    }
    
    return scanner.analyze_project(test_project)


def print_js_results(result):
    print("=" * 70)
    print("🔍 JavaScript/TypeScript 취약점 스캐너 테스트 결과")
    print("=" * 70)
    
    summary = result['summary']
    print(f"총 발견된 취약점: {summary['total_vulnerabilities']}개")
    print(f"🔴 Critical: {summary['critical']}")
    print(f"🟠 High: {summary['high']}")
    print(f"🟡 Medium: {summary['medium']}")
    print(f"🟢 Low: {summary['low']}")
    print()
    
    # 취약점 타입별 분류
    vuln_types = {}
    for vuln in result['vulnerabilities']:
        vuln_type = vuln['type']
        if vuln_type not in vuln_types:
            vuln_types[vuln_type] = 0
        vuln_types[vuln_type] += 1
    
    print("📊 취약점 타입별 분류:")
    print("-" * 40)
    for vuln_type, count in sorted(vuln_types.items()):
        print(f"  {vuln_type}: {count}개")
    print()
    
    print("🔍 발견된 주요 취약점들:")
    print("-" * 50)
    
    # 심각도별로 정렬
    sorted_vulns = sorted(result['vulnerabilities'], 
                         key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[x['severity']], 
                         reverse=True)
    
    for i, vuln in enumerate(sorted_vulns[:15], 1):  # 상위 15개만 표시
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
        print(f"    코드: {vuln['code_snippet'][:60]}...")
        print()
    
    print("💡 JavaScript 보안 권장사항:")
    print("-" * 50)
    js_recommendations = [
        "1. eval(), Function() 생성자 사용 금지",
        "2. innerHTML 대신 textContent 사용",
        "3. Template literal에서 사용자 입력 검증",
        "4. child_process 사용 시 shell=false 옵션",
        "5. 파라미터화된 쿼리 사용",
        "6. Content Security Policy (CSP) 구현",
        "7. 입력 데이터 타입 검증 및 인코딩"
    ]
    
    for rec in js_recommendations:
        print(f"  {rec}")
    print()


if __name__ == "__main__":
    print("JavaScript/TypeScript 취약점 스캐너 테스트를 시작합니다...")
    print()
    
    try:
        # 스캔 실행
        result = create_js_test()
        
        # 결과 출력
        print_js_results(result)
        
        # JSON 결과도 저장
        with open('js_test_result.json', 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        print("결과가 js_test_result.json 파일에 저장되었습니다.")
        
        total_vulns = result['summary']['total_vulnerabilities']
        if total_vulns > 0:
            print(f"\n✅ 테스트 완료! {total_vulns}개의 JavaScript 취약점이 탐지되었습니다.")
        else:
            print("\n⚠️  취약점이 탐지되지 않았습니다. 패턴을 확인해주세요.")
            
    except Exception as e:
        print(f"❌ 테스트 중 오류 발생: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)