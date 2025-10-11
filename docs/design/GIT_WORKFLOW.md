# Git Workflow Guide - rs-sage-core Refactoring

> **브랜치 전략 및 PR 워크플로우**

## 🌳 브랜치 구조

```
main (프로덕션)
  └── dev (개발 베이스)
       ├── feat/phase1-project-structure
       ├── feat/phase1-core-module
       ├── feat/phase1-crypto-manager
       ├── feat/phase1-crypto-storage
       ├── feat/phase1-rfc9421-builder
       ├── feat/phase2-did-types
       ├── feat/phase2-did-manager
       ├── feat/phase2-ethereum-client
       ├── feat/phase2-solana-client
       ├── feat/phase2-multichain
       ├── feat/phase3-nonce-manager
       ├── feat/phase3-dedupe-detector
       ├── feat/phase3-verification-pipeline
       ├── feat/phase4-core-integration
       ├── feat/phase4-public-api
       └── feat/phase4-interop-tests
```

## 📋 브랜치 명명 규칙

### 형식
```
<type>/<phase>-<description>
```

### 타입
- `feat/`: 새로운 기능 구현
- `fix/`: 버그 수정
- `docs/`: 문서 작업
- `refactor/`: 리팩토링
- `test/`: 테스트 추가/수정
- `chore/`: 기타 작업

### 예시
```
feat/phase1-core-module
feat/phase2-ethereum-client
fix/phase1-crypto-storage-race-condition
docs/phase1-api-documentation
test/phase2-did-integration
```

## 🔄 워크플로우

### 1. Phase 1 작업 시작

#### Step 1: dev 브랜치에서 시작
```bash
cd rs-sage-core

# dev 브랜치로 이동
git checkout dev

# 최신 상태 업데이트
git pull origin dev
```

#### Step 2: Task별 브랜치 생성

**Task 1-1: 프로젝트 구조 재설계**
```bash
git checkout -b feat/phase1-project-structure

# 작업: 디렉토리 구조 생성, 모듈 스캐폴딩
mkdir -p src/core src/crypto/storage tests/integration examples

# 커밋
git add .
git commit -m "feat(phase1): setup project structure and module scaffolding

- Create core/ directory structure
- Create crypto/storage/ directory
- Setup tests/integration/ directory
- Add examples/ directory"

# 푸시
git push -u origin feat/phase1-project-structure
```

**Task 1-2: Core 모듈 구현**
```bash
# dev에서 새 브랜치
git checkout dev
git pull origin dev
git checkout -b feat/phase1-core-module

# 작업: Message 타입 및 VerificationService
# src/core/mod.rs, message.rs, types.rs 생성

git add src/core/
git commit -m "feat(phase1): implement core module with Message and types

- Add Message struct with builder pattern
- Add VerificationOptions and VerificationResult
- Add VerificationService skeleton
- Add comprehensive tests"

git push -u origin feat/phase1-core-module
```

**Task 1-3: CryptoManager 구현**
```bash
git checkout dev
git pull origin dev
git checkout -b feat/phase1-crypto-manager

# 작업: CryptoManager 및 KeyStorage trait
# src/crypto/manager.rs, storage/mod.rs 생성

git add src/crypto/
git commit -m "feat(phase1): implement CryptoManager and KeyStorage trait

- Add CryptoManager for key management
- Add KeyStorage trait for storage abstraction
- Add MemoryKeyStorage implementation
- Add FileKeyStorage implementation
- Add comprehensive unit tests"

git push -u origin feat/phase1-crypto-manager
```

**Task 1-4: RFC 9421 확장**
```bash
git checkout dev
git pull origin dev
git checkout -b feat/phase1-rfc9421-builder

# 작업: MessageBuilder 및 고수준 API
# src/rfc9421/message_builder.rs 생성

git add src/rfc9421/
git commit -m "feat(phase1): add high-level MessageBuilder API

- Add MessageBuilder for convenient message creation
- Add integration with existing HttpSigner
- Add examples and tests"

git push -u origin feat/phase1-rfc9421-builder
```

### 2. Pull Request 생성

#### PR 템플릿

```markdown
## 📋 작업 내용

### Phase 1: Task X - [작업명]

- [ ] 구현 완료
- [ ] 테스트 작성 완료
- [ ] 문서 작성 완료
- [ ] cargo fmt 통과
- [ ] cargo clippy 통과
- [ ] cargo test 통과

## 🔍 변경사항

- 추가된 파일: `src/core/mod.rs`, `src/core/message.rs`
- 수정된 파일: `src/lib.rs`
- 테스트: `src/core/message.rs::tests`

## 📊 테스트 결과

```bash
cargo test --lib core
# 결과 붙여넣기
```

## 📖 관련 문서

- [PHASE_1_DESIGN.md](./docs/design/PHASE_1_DESIGN.md)
- [IMPLEMENTATION_PLAN.md](./docs/design/IMPLEMENTATION_PLAN.md)

## ✅ 체크리스트

- [ ] 코드 리뷰 요청
- [ ] CI/CD 통과
- [ ] 문서 업데이트
```

#### GitHub에서 PR 생성

1. **GitHub 웹사이트**에서 repository 이동
2. **Pull requests** 탭 클릭
3. **New pull request** 클릭
4. **base**: `dev` ← **compare**: `feat/phase1-xxx` 선택
5. 제목 및 설명 작성
6. **Create pull request** 클릭

#### 또는 CLI 사용 (gh CLI)

```bash
# PR 생성
gh pr create \
  --base dev \
  --head feat/phase1-core-module \
  --title "feat(phase1): implement core module" \
  --body-file .github/pull_request_template.md

# PR 리스트 확인
gh pr list

# PR 상태 확인
gh pr status
```

### 3. 코드 리뷰 및 머지

#### 리뷰 프로세스

1. **자동 CI/CD 실행**
   - `cargo fmt --check`
   - `cargo clippy -- -D warnings`
   - `cargo test --all-features`
   - `cargo doc --no-deps`

2. **코드 리뷰 수행**
   - 설계 문서와 일치 확인
   - 테스트 커버리지 확인
   - 코드 품질 확인

3. **변경 요청 또는 승인**

4. **dev 브랜치로 머지**
   ```bash
   # GitHub에서 "Squash and merge" 선택
   # 또는 CLI
   gh pr merge feat/phase1-core-module --squash --delete-branch
   ```

### 4. dev → main 머지 (Phase 완료 시)

```bash
# Phase 1 전체 완료 후
git checkout main
git pull origin main
git merge dev

# 또는 PR 생성
gh pr create \
  --base main \
  --head dev \
  --title "feat: Phase 1 - Core Infrastructure Complete" \
  --body "Phase 1 implementation complete. Ready for production."
```

## 🎯 Phase별 브랜치 전략

### Phase 1: 핵심 인프라 (5개 브랜치)

| 브랜치 | 작업 내용 | 예상 시간 |
|--------|----------|----------|
| `feat/phase1-project-structure` | 프로젝트 구조 재설계 | 1일 |
| `feat/phase1-core-module` | Core 모듈 (Message, types) | 2일 |
| `feat/phase1-crypto-manager` | CryptoManager + Storage | 2-3일 |
| `feat/phase1-rfc9421-builder` | MessageBuilder API | 1-2일 |
| `feat/phase1-integration-tests` | Phase 1 통합 테스트 | 1일 |

### Phase 2: DID 시스템 (5개 브랜치)

| 브랜치 | 작업 내용 | 예상 시간 |
|--------|----------|----------|
| `feat/phase2-did-types` | DID 기본 타입 | 1일 |
| `feat/phase2-did-manager` | DIDManager + traits | 2-3일 |
| `feat/phase2-ethereum-client` | Ethereum 연동 | 3-5일 |
| `feat/phase2-solana-client` | Solana 연동 | 3-5일 |
| `feat/phase2-multichain` | MultiChain 통합 | 2-3일 |

### Phase 3: 메시지 처리 (3개 브랜치)

| 브랜치 | 작업 내용 | 예상 시간 |
|--------|----------|----------|
| `feat/phase3-nonce-manager` | NonceManager | 1-2일 |
| `feat/phase3-message-validation` | Dedupe + Order | 2-3일 |
| `feat/phase3-verification-pipeline` | 통합 검증 | 1-2일 |

### Phase 4: 통합 & 테스트 (3개 브랜치)

| 브랜치 | 작업 내용 | 예상 시간 |
|--------|----------|----------|
| `feat/phase4-core-integration` | Core 통합 레이어 | 2-3일 |
| `feat/phase4-public-api` | 공개 API + 문서 | 2-3일 |
| `feat/phase4-interop-tests` | Go 상호운용성 | 2-3일 |

## 📝 커밋 메시지 규칙

### 형식
```
<type>(<scope>): <subject>

<body>

<footer>
```

### 타입
- `feat`: 새로운 기능
- `fix`: 버그 수정
- `docs`: 문서 작업
- `style`: 코드 포맷팅
- `refactor`: 리팩토링
- `test`: 테스트 추가/수정
- `chore`: 빌드/설정 변경

### Scope
- `phase1`, `phase2`, `phase3`, `phase4`
- 또는 모듈명: `core`, `crypto`, `did`, `rfc9421`

### 예시

```
feat(phase1): implement Message type with builder pattern

- Add Message struct with all required fields
- Add MessageBuilder with fluent API
- Add validation and error handling
- Add comprehensive unit tests

Closes #123
```

```
fix(crypto): resolve race condition in KeyStorage

FileKeyStorage had a race condition when accessing cache.
Fixed by using DashMap instead of RwLock<HashMap>.

Fixes #456
```

## 🔒 보호된 브랜치 규칙

### main 브랜치
- ✅ Require PR before merging
- ✅ Require status checks to pass
- ✅ Require code review (1+ approvals)
- ✅ Require up-to-date branches
- ❌ No force push

### dev 브랜치
- ✅ Require PR before merging
- ✅ Require status checks to pass
- ⚠️ Require code review (optional)
- ✅ Require up-to-date branches
- ❌ No force push

## 🚨 긴급 수정 (Hotfix)

```bash
# main에서 직접 브랜치 생성
git checkout main
git pull origin main
git checkout -b hotfix/critical-bug-fix

# 수정 작업
git add .
git commit -m "fix: critical security vulnerability in xyz"

# main과 dev 모두에 머지
git push -u origin hotfix/critical-bug-fix

# PR 생성 (main으로)
gh pr create --base main --head hotfix/critical-bug-fix

# dev에도 적용
git checkout dev
git cherry-pick <commit-hash>
git push origin dev
```

## 📊 진행 상황 추적

### 브랜치 상태 확인
```bash
# 모든 브랜치 확인
git branch -a

# 브랜치별 마지막 커밋
git for-each-ref --sort=-committerdate refs/heads/ \
  --format='%(refname:short) - %(committerdate:short) - %(subject)'

# PR 상태
gh pr list --state all
```

### Phase 진행률
```bash
# Phase 1 브랜치들
git branch | grep phase1

# Phase 1 머지된 PR
gh pr list --base dev --state merged | grep phase1
```

## 🎓 Best Practices

### 1. 작은 단위로 커밋
```bash
# ❌ 나쁜 예
git add .
git commit -m "feat: implement everything"

# ✅ 좋은 예
git add src/core/message.rs
git commit -m "feat(core): add Message struct"

git add src/core/types.rs
git commit -m "feat(core): add VerificationOptions types"
```

### 2. 커밋 전 확인
```bash
# 포맷 확인
cargo fmt --check

# Lint 확인
cargo clippy -- -D warnings

# 테스트 실행
cargo test

# 빌드 확인
cargo build --all-features
```

### 3. PR 전 rebase
```bash
# dev 최신 상태 가져오기
git checkout dev
git pull origin dev

# 작업 브랜치에서 rebase
git checkout feat/phase1-core-module
git rebase dev

# 충돌 해결 후
git rebase --continue
git push --force-with-lease
```

### 4. 브랜치 정리
```bash
# 머지된 브랜치 삭제
git branch --merged dev | grep -v "^\*\|dev\|main" | xargs git branch -d

# 리모트 추적 브랜치 정리
git fetch --prune
```

## 🔗 유용한 Git 명령어

```bash
# 현재 브랜치의 upstream 확인
git branch -vv

# 특정 파일의 변경 이력
git log --follow -- src/core/message.rs

# 커밋 되돌리기 (작업 유지)
git reset --soft HEAD~1

# 특정 커밋의 변경사항 확인
git show <commit-hash>

# 브랜치 간 차이 확인
git diff dev..feat/phase1-core-module

# 스태시 활용
git stash save "WIP: message builder"
git stash list
git stash pop
```

---

**작성일**: 2025-01-27
**버전**: 1.0
**상태**: 활성
