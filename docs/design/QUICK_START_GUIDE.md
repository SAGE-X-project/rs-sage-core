# rs-sage-core 리팩토링 빠른 시작 가이드

> **목적**: 개발자가 즉시 구현을 시작할 수 있도록 단계별 지침 제공

## 🚀 즉시 시작하기

### 1단계: 환경 준비 (5분)

```bash
# 현재 위치 확인
cd /Users/0xtopaz/work/github/sage-x-project/final-ready/rs-sage-core

# Rust 버전 확인 (1.70 이상 필요)
rustc --version

# 필요한 도구 설치
cargo install cargo-watch  # 자동 빌드
cargo install cargo-expand # 매크로 확장 확인
```

### 2단계: Cargo.toml 업데이트 (10분)

`Cargo.toml`을 열고 다음 의존성을 추가하세요:

```toml
[dependencies]
# Phase 1 새 의존성
dashmap = "5.5"
parking_lot = "0.12"
uuid = { version = "1.6", features = ["v4"] }

# 기존 의존성은 유지
```

### 3단계: 디렉토리 구조 생성 (5분)

```bash
# Phase 1 디렉토리 생성
mkdir -p src/core
mkdir -p src/crypto/storage
mkdir -p tests/integration
mkdir -p examples

# docs는 이미 생성됨
```

### 4단계: 첫 번째 파일 생성 (15분)

**src/core/mod.rs** 파일을 생성하고 다음 내용을 추가:

```rust
//! Core integration layer for SAGE

pub mod message;
pub mod types;

pub use message::Message;
pub use types::{VerificationOptions, VerificationResult};
```

### 5단계: 빌드 테스트 (5분)

```bash
# 빌드 확인
cargo build

# 테스트 실행
cargo test

# 문서 생성
cargo doc --open
```

## 📋 Day-by-Day 구현 가이드

### Day 1: 기본 구조 (2-3시간)

**목표**: 모든 모듈 스캐폴딩 완료

**체크리스트**:
- [ ] `src/core/mod.rs` 생성
- [ ] `src/core/message.rs` 스캐폴딩
- [ ] `src/core/types.rs` 스캐폴딩
- [ ] `src/crypto/manager.rs` 스캐폴딩
- [ ] `src/crypto/storage/mod.rs` 스캐폴딩
- [ ] `cargo build` 성공

**실행 명령**:
```bash
# 자동 빌드 감시
cargo watch -x build

# 다른 터미널에서 파일 생성
touch src/core/{mod,message,types}.rs
touch src/crypto/{manager.rs,storage/mod.rs}
```

### Day 2: Message 타입 (3-4시간)

**목표**: 완전한 Message 및 MessageBuilder 구현

**참조**: `docs/design/PHASE_1_DESIGN.md` → Task 2.1

**테스트**:
```bash
cargo test --lib core::message
```

### Day 3: KeyStorage (3-4시간)

**목표**: MemoryKeyStorage 및 FileKeyStorage 완성

**참조**: `docs/design/PHASE_1_DESIGN.md` → Task 3

**테스트**:
```bash
cargo test --lib crypto::storage
```

### Day 4: CryptoManager (2-3시간)

**목표**: CryptoManager 통합 및 Core 연결

**참조**: `docs/design/PHASE_1_DESIGN.md` → Task 3.4

**테스트**:
```bash
cargo test --lib crypto::manager
cargo test --lib core
```

### Day 5: RFC 9421 확장 (3-4시간)

**목표**: MessageBuilder 고수준 API

**참조**: `docs/design/PHASE_1_DESIGN.md` → Task 4

**테스트**:
```bash
cargo test --lib rfc9421::message_builder
```

### Day 6-7: 통합 테스트 (4-6시간)

**목표**: End-to-end 테스트 및 문서화

**테스트**:
```bash
cargo test --test phase1_tests
cargo doc --no-deps --open
```

## 🔧 유용한 개발 명령어

### 빌드 & 테스트

```bash
# 빠른 체크
cargo check

# 전체 빌드
cargo build --all-features

# 특정 feature만
cargo build --features "crypto,rfc9421"

# 테스트 (상세)
cargo test -- --nocapture

# 벤치마크
cargo bench

# 코드 포맷
cargo fmt

# Lint
cargo clippy -- -D warnings
```

### 문서화

```bash
# 문서 생성 및 열기
cargo doc --open

# private 항목 포함
cargo doc --document-private-items

# 예제 테스트
cargo test --doc
```

### 디버깅

```bash
# 매크로 확장 확인
cargo expand

# 의존성 트리
cargo tree

# 감시 모드 (파일 변경 시 자동 빌드)
cargo watch -x check -x test
```

## 📊 진행 상황 추적

### Phase 1 진행률 계산

```bash
# 전체 TODO 카운트
rg "TODO|FIXME" src/ --count

# 테스트 통과율
cargo test 2>&1 | rg "test result"

# 문서화율
cargo doc --no-deps 2>&1 | rg "warning"
```

## 🐛 일반적인 문제 해결

### 문제 1: DashMap 컴파일 에러

```bash
# 해결: Rust 버전 업데이트
rustup update stable
```

### 문제 2: parking_lot 빌드 실패

```bash
# 해결: 시스템 라이브러리 설치 (macOS)
brew install llvm

# Linux
sudo apt-get install build-essential
```

### 문제 3: 테스트 타임아웃

```bash
# 해결: 타임아웃 증가
cargo test -- --test-threads=1
```

## 📚 참조 문서

### 내부 문서
- [전체 구현 계획](./IMPLEMENTATION_PLAN.md)
- [Phase 1 상세 설계](./PHASE_1_DESIGN.md)
- [Phase 2 상세 설계](./PHASE_2_DESIGN.md) (작성 예정)
- [Phase 3 상세 설계](./PHASE_3_DESIGN.md) (작성 예정)
- [Phase 4 상세 설계](./PHASE_4_DESIGN.md) (작성 예정)

### 외부 리소스
- [Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [ethers-rs Docs](https://docs.rs/ethers/)
- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)

## 🎯 성공 기준

### Phase 1 완료 조건

- [ ] 모든 파일이 `cargo build` 통과
- [ ] 모든 테스트가 `cargo test` 통과
- [ ] 문서가 `cargo doc` 경고 없이 생성
- [ ] 통합 테스트 시나리오 통과
- [ ] 코드 리뷰 완료

### 품질 메트릭

| 메트릭 | 목표 | 측정 방법 |
|--------|------|----------|
| 테스트 통과율 | 100% | `cargo test` |
| 문서 커버리지 | >90% | `cargo doc` |
| 코드 커버리지 | >80% | `cargo tarpaulin` |
| Clippy 경고 | 0개 | `cargo clippy` |
| 컴파일 시간 | <30초 | `cargo build --timings` |

## 🔄 일일 워크플로우

### 아침 (시작 시)

```bash
# 최신 코드 받기
git pull

# 의존성 업데이트 확인
cargo update --dry-run

# 빠른 체크
cargo check
```

### 작업 중

```bash
# 백그라운드 감시
cargo watch -x check -x test &

# 코드 작성...

# 주기적으로 포맷 및 Lint
cargo fmt && cargo clippy
```

### 저녁 (커밋 전)

```bash
# 전체 테스트
cargo test --all-features

# 문서 확인
cargo doc --no-deps

# 커밋
git add .
git commit -m "feat(phase1): implement Message type"
```

## 💡 팁 & 트릭

### 1. 빠른 반복 개발

```bash
# 특정 테스트만 실행
cargo test test_message_builder -- --exact

# 변경된 부분만 재컴파일
cargo build --incremental
```

### 2. 디버그 출력

```rust
// 임시 디버그
dbg!(&message);

// 프로덕션 로깅 (향후)
log::debug!("Message: {:?}", message);
```

### 3. 에러 추적

```rust
use anyhow::Context;

fn my_function() -> Result<()> {
    something()
        .context("Failed to do something")?;
    Ok(())
}
```

## 📞 도움 요청

### 막혔을 때

1. **문서 확인**: `docs/design/` 디렉토리
2. **기존 코드 참조**: sage/ Go 구현
3. **커뮤니티**: Rust 포럼, Discord
4. **AI 도움**: Claude, ChatGPT로 특정 문제 질의

### 코드 리뷰 준비

```bash
# Self-review 체크리스트
cargo fmt --check
cargo clippy -- -D warnings
cargo test --all-features
cargo doc --no-deps
```

---

**이제 시작할 준비가 되었습니다!** 🚀

`Phase 1: Day 1`부터 시작하세요.

궁금한 점이 있으면 `docs/design/` 디렉토리의 상세 설계 문서를 참조하세요.
