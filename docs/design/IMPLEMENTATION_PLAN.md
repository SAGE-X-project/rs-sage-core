# rs-sage-core 상세 구현 계획서

> **목표**: sage/ Go 구현과 동일한 기능을 제공하는 Rust 기반 SAGE Core 라이브러리 구축

## 📋 전체 개요

### 현재 상태 (As-Is)
- **라인 수**: ~3,554 LOC
- **모듈**: crypto, rfc9421, formats, ffi, wasm
- **범위**: 기본 암호화 + RFC 9421 HTTP 서명

### 목표 상태 (To-Be)
- **라인 수**: ~10,000-15,000 LOC (예상)
- **모듈**: core, crypto, rfc9421, did, message, formats, ffi, wasm
- **범위**: 완전한 AI 에이전트 보안 통신 시스템

## 🏗️ 최종 디렉토리 구조

```
rs-sage-core/
├── Cargo.toml                   # 의존성 및 feature flags
├── src/
│   ├── lib.rs                   # 라이브러리 진입점
│   │
│   ├── core/                    # 🆕 통합 레이어
│   │   ├── mod.rs              # Core 구조체, 통합 API
│   │   ├── message.rs          # Message 타입 정의
│   │   ├── verification_service.rs  # 통합 검증 서비스
│   │   └── types.rs            # 공통 타입
│   │
│   ├── crypto/                  # ✏️ 기존 확장
│   │   ├── mod.rs
│   │   ├── keys.rs             # 기존 유지
│   │   ├── ed25519.rs          # 기존 유지
│   │   ├── secp256k1.rs        # 기존 유지
│   │   ├── signature.rs        # 기존 유지
│   │   ├── manager.rs          # 🆕 CryptoManager
│   │   └── storage/            # 🆕 키 저장소
│   │       ├── mod.rs          # KeyStorage trait
│   │       ├── memory.rs       # 메모리 저장소
│   │       └── file.rs         # 파일 저장소
│   │
│   ├── rfc9421/                 # ✏️ 기존 확장
│   │   ├── mod.rs
│   │   ├── signer.rs           # 기존 유지
│   │   ├── verifier.rs         # 기존 유지
│   │   ├── canonicalize.rs     # 기존 유지
│   │   ├── components.rs       # 기존 유지
│   │   ├── message_builder.rs  # 🆕 고수준 빌더
│   │   └── validator.rs        # 🆕 메타데이터 검증
│   │
│   ├── did/                     # 🆕 DID 시스템
│   │   ├── mod.rs              # DIDManager
│   │   ├── types.rs            # AgentDID, AgentMetadata 등
│   │   ├── manager.rs          # 통합 DID 관리자
│   │   ├── resolver.rs         # MultiChainResolver
│   │   ├── registry.rs         # MultiChainRegistry
│   │   ├── verification.rs     # MetadataVerifier
│   │   └── chain/              # 블록체인 구현
│   │       ├── mod.rs          # Registry/Resolver traits
│   │       ├── ethereum.rs     # Ethereum 클라이언트
│   │       └── solana.rs       # Solana 클라이언트
│   │
│   ├── message/                 # 🆕 메시지 처리
│   │   ├── mod.rs
│   │   ├── nonce.rs            # NonceManager
│   │   ├── dedupe.rs           # DedupeDetector
│   │   └── order.rs            # OrderManager
│   │
│   ├── formats/                 # 기존 유지
│   │   └── mod.rs
│   │
│   ├── error.rs                 # 기존 유지
│   │
│   ├── ffi/                     # 기존 유지
│   │   └── mod.rs
│   │
│   └── wasm/                    # 기존 유지
│       └── mod.rs
│
├── tests/                       # 통합 테스트
│   ├── integration/
│   │   ├── crypto_tests.rs
│   │   ├── did_tests.rs
│   │   ├── message_tests.rs
│   │   └── interop_tests.rs    # Go 구현과 상호운용성
│   └── test_utils/
│       └── mod.rs
│
├── benches/                     # 벤치마크
│   └── crypto_benchmarks.rs
│
├── examples/                    # 예제 코드
│   ├── basic_usage.rs
│   ├── ethereum_did.rs
│   ├── solana_did.rs
│   └── message_verification.rs
│
└── docs/
    ├── design/                  # 설계 문서
    │   ├── IMPLEMENTATION_PLAN.md  # 이 파일
    │   ├── PHASE_1_DESIGN.md
    │   ├── PHASE_2_DESIGN.md
    │   ├── PHASE_3_DESIGN.md
    │   └── PHASE_4_DESIGN.md
    └── api/                     # API 문서
        └── README.md
```

## 📦 의존성 설계

### Cargo.toml 구조

```toml
[package]
name = "sage_crypto_core"
version = "0.2.0"
edition = "2021"

[dependencies]
# 기존 의존성
ed25519-dalek = "2.1"
k256 = { version = "0.11", features = ["ecdsa"] }
signature = "1.6"
rand = "0.8"
sha2 = "0.10"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.21"
hex = "0.4"
pem = "1.1"
thiserror = "1.0"
anyhow = "1.0"
http = "0.2"
chrono = "0.4"

# 🆕 Phase 1 의존성
dashmap = "5.5"              # 동시성 안전 HashMap
parking_lot = "0.12"          # 빠른 RwLock

# 🆕 Phase 2 의존성 (DID)
tokio = { version = "1.35", features = ["full"], optional = true }
async-trait = { version = "0.1", optional = true }

# Ethereum
ethers = { version = "2.0", optional = true }
# Solana
solana-sdk = { version = "1.17", optional = true }
solana-client = { version = "1.17", optional = true }

# 🆕 Phase 3 의존성 (메시지 처리)
uuid = { version = "1.6", features = ["v4"] }

# 기존 선택적 의존성
libc = { version = "0.2", optional = true }
wasm-bindgen = { version = "0.2", optional = true }
wasm-bindgen-futures = { version = "0.4", optional = true }
js-sys = { version = "0.3", optional = true }
web-sys = { version = "0.3", features = ["Headers", "Request", "Response"], optional = true }
getrandom = { version = "0.2", features = ["js"], optional = true }
console_error_panic_hook = { version = "0.1", optional = true }

[dev-dependencies]
tokio = { version = "1.35", features = ["full", "test-util"] }
criterion = "0.5"
proptest = "1.0"

[features]
default = ["std"]
std = []

# 모듈별 feature
crypto = []
rfc9421 = ["crypto", "http"]
message = []

# DID 관련
did = ["crypto", "tokio", "async-trait"]
ethereum = ["did", "ethers"]
solana = ["did", "solana-sdk", "solana-client"]

# 전체 기능
full = ["crypto", "rfc9421", "did", "ethereum", "solana", "message"]

# 플랫폼 바인딩
ffi = ["libc"]
wasm = ["wasm-bindgen", "wasm-bindgen-futures", "js-sys", "web-sys", "getrandom", "console_error_panic_hook"]
```

## 🎯 Phase별 구현 계획

### Phase 1: 핵심 인프라 (5-7일)

**목표**: 기본 구조 확립 및 crypto 확장

**작업 항목**:
1. 프로젝트 구조 재설계
2. Core 모듈 스캐폴딩
3. CryptoManager + KeyStorage
4. RFC 9421 확장

**산출물**:
- `src/core/` 모듈
- `src/crypto/manager.rs`, `src/crypto/storage/`
- `src/rfc9421/message_builder.rs`

**완료 기준**:
- [ ] 전체 모듈 구조 생성 완료
- [ ] CryptoManager로 키 생성/저장/로드 가능
- [ ] MessageBuilder로 RFC 9421 메시지 생성 가능
- [ ] 유닛 테스트 통과

### Phase 2: DID 시스템 (10-14일)

**목표**: 블록체인 기반 DID 관리

**작업 항목**:
1. DID 기본 타입 및 traits
2. Ethereum 클라이언트
3. Solana 클라이언트
4. MultiChain 통합

**산출물**:
- `src/did/` 전체 모듈
- Ethereum/Solana 블록체인 연동

**완료 기준**:
- [ ] DID 생성 및 파싱 가능
- [ ] Ethereum 테스트넷에서 DID 등록/조회 가능
- [ ] Solana 테스트넷에서 DID 등록/조회 가능
- [ ] 통합 테스트 통과

### Phase 3: 메시지 처리 (4-6일)

**목표**: 메시지 무결성 및 순서 보장

**작업 항목**:
1. NonceManager
2. DedupeDetector
3. OrderManager
4. 검증 파이프라인 통합

**산출물**:
- `src/message/` 모듈
- 통합 검증 서비스

**완료 기준**:
- [ ] Nonce 생성 및 검증
- [ ] 중복 메시지 탐지
- [ ] 순서 보장 로직
- [ ] 통합 테스트 통과

### Phase 4: 통합 및 테스트 (5-8일)

**목표**: 전체 시스템 통합 및 Go 구현과 호환성

**작업 항목**:
1. Core 통합 레이어
2. 공개 API 설계
3. 문서화
4. 상호운용성 테스트

**산출물**:
- 완전한 Core API
- 종합 문서
- 상호운용성 검증

**완료 기준**:
- [ ] sage/ Go 구현과 동일한 API 제공
- [ ] Go로 생성된 서명을 Rust로 검증 가능
- [ ] Rust로 생성된 서명을 Go로 검증 가능
- [ ] 전체 통합 테스트 통과

## 📊 구현 우선순위 매트릭스

| 기능 | 복잡도 | 중요도 | 의존성 | 우선순위 |
|------|--------|--------|--------|----------|
| Core 구조 | 중 | 높음 | 없음 | P0 |
| CryptoManager | 중 | 높음 | Core | P0 |
| KeyStorage | 낮 | 중간 | CryptoManager | P1 |
| MessageBuilder | 중 | 높음 | 없음 | P0 |
| DID Types | 낮 | 높음 | 없음 | P0 |
| DIDManager | 중 | 높음 | DID Types | P0 |
| Ethereum Client | 높음 | 높음 | DIDManager | P0 |
| Solana Client | 높음 | 높음 | DIDManager | P0 |
| NonceManager | 낮 | 중간 | 없음 | P1 |
| DedupeDetector | 낮 | 중간 | 없음 | P1 |
| OrderManager | 중 | 낮 | 없음 | P2 |
| VerificationService | 중 | 높음 | 모든 모듈 | P0 |

## 🔗 의존성 그래프

```
Core
 ├─ crypto::CryptoManager
 │   └─ crypto::KeyStorage
 ├─ did::DIDManager
 │   ├─ did::MultiChainRegistry
 │   │   ├─ did::chain::ethereum::EthereumClient
 │   │   └─ did::chain::solana::SolanaClient
 │   └─ did::MultiChainResolver
 │       ├─ did::chain::ethereum::EthereumClient
 │       └─ did::chain::solana::SolanaClient
 ├─ message::NonceManager
 ├─ message::DedupeDetector
 ├─ message::OrderManager
 ├─ rfc9421::HttpSigner
 ├─ rfc9421::HttpVerifier
 └─ core::VerificationService
     ├─ did::DIDManager
     ├─ rfc9421::HttpVerifier
     └─ message::*
```

## 📝 구현 가이드라인

### 코드 스타일

1. **명명 규칙**:
   - 타입: `PascalCase`
   - 함수/변수: `snake_case`
   - 상수: `SCREAMING_SNAKE_CASE`
   - Trait: `PascalCase` (형용사 형태 선호)

2. **에러 처리**:
   - `Result<T, Error>` 일관되게 사용
   - `thiserror`로 커스텀 에러 정의
   - `anyhow`는 최상위 애플리케이션에서만

3. **비동기 처리**:
   - DID 연동은 모두 `async`
   - `tokio` 런타임 사용
   - `async-trait` 매크로 활용

4. **문서화**:
   - 모든 public API에 rustdoc 주석
   - 예제 코드 포함 (`/// # Examples`)
   - 에러 케이스 명시 (`/// # Errors`)

### 테스트 전략

1. **유닛 테스트**: 각 모듈별 `#[cfg(test)] mod tests`
2. **통합 테스트**: `tests/integration/` 디렉토리
3. **벤치마크**: `benches/` 디렉토리
4. **상호운용성 테스트**: Go 구현과 크로스 검증

### 성능 고려사항

1. **동시성**:
   - `Arc` + `RwLock` 대신 `DashMap` 사용 (더 빠른 동시 접근)
   - `parking_lot::RwLock` 사용 (std보다 빠름)

2. **메모리**:
   - 큰 데이터는 `Box` 또는 `Arc`로 감싸기
   - Clone 최소화

3. **네트워크**:
   - 블록체인 조회 결과 캐싱
   - 배치 요청으로 최적화

## 🎓 학습 리소스

### Rust 비동기 프로그래밍
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [async-trait Guide](https://rust-lang.github.io/async-book/)

### 블록체인 SDK
- [ethers-rs Documentation](https://docs.rs/ethers/)
- [Solana SDK Guide](https://docs.solana.com/developing/clients/rust-api)

### RFC 9421
- [RFC 9421 Specification](https://www.rfc-editor.org/rfc/rfc9421.html)

## 📅 마일스톤

| 날짜 | 마일스톤 | 완료 기준 |
|------|----------|-----------|
| D+7 | Phase 1 완료 | Core 구조 + Crypto 확장 |
| D+21 | Phase 2 완료 | DID 시스템 완성 |
| D+27 | Phase 3 완료 | 메시지 처리 완성 |
| D+35 | Phase 4 완료 | 전체 통합 및 검증 |

## ⚠️ 리스크 및 완화 전략

| 리스크 | 영향도 | 완화 전략 |
|--------|--------|-----------|
| Ethereum SDK 복잡도 | 높음 | 단계별 학습, 예제 먼저 구현 |
| Solana SDK 복잡도 | 높음 | 단계별 학습, 예제 먼저 구현 |
| 비동기 복잡도 | 중간 | Tokio 문서 숙지, 간단한 예제부터 |
| Go 호환성 | 높음 | 지속적인 상호운용성 테스트 |
| 일정 지연 | 중간 | 우선순위 조정, Phase 3 일부 연기 가능 |

## 🔄 다음 단계

1. **Phase 1 상세 설계 검토** → `PHASE_1_DESIGN.md`
2. **Phase 1 구현 시작**
3. **주간 진행 상황 리뷰**

---

**작성일**: 2025-01-27
**작성자**: SAGE Development Team
**버전**: 1.0
