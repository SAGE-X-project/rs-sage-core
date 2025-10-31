# Next Phase TODO List

**Generated**: 2025-10-28
**Previous Phase Completion**: 100%
**Current Test Coverage**: 73.49% (line coverage)

---

## 📊 Current Status

### ✅ Completed (Phase Current)
- Algorithm Registry (93.72% coverage)
- X25519 KeyPair Wrapper (99.07% coverage)
- Multi-Chain Manager (new module)
- Comprehensive Test Suite (+20 tests, 250 total)
- Documentation (X25519 & Multi-Chain Manager guides)

### 📈 Coverage Analysis

**High Coverage (>90%)**:
- ✅ crypto/x25519.rs: 99.07%
- ✅ crypto/storage/memory.rs: 98.59%
- ✅ transport/mock.rs: 96.38%
- ✅ transport/manager.rs: 95.00%
- ✅ crypto/multi_key.rs: 94.82%
- ✅ crypto/rotation.rs: 94.15%
- ✅ crypto/algorithm_registry.rs: 93.72%

**Medium Coverage (70-90%)**:
- 🟡 crypto/ed25519.rs: 82.83%
- 🟡 blockchain/types.rs: 81.37%
- 🟡 validation/validators.rs: 89.94%
- 🟡 crypto/p256.rs: 89.58%
- 🟡 crypto/rsa.rs: 89.36%
- 🟡 core/message.rs: 89.09%

**Low Coverage (<70%)** - 개선 필요:
- ⚠️ blockchain/ethereum/client.rs: **6.45%**
- ⚠️ rfc9421/verifier.rs: **5.90%**
- ⚠️ rfc9421/mod.rs: **7.55%**
- ⚠️ blockchain/ethereum/resolver.rs: **14.75%**
- ⚠️ crypto/signature.rs: **21.43%** (개선 중)
- ⚠️ core/verification_service.rs: **50.00%**
- ⚠️ formats/mod.rs: **55.84%**
- ⚠️ transport/http.rs: **58.88%**
- ⚠️ crypto/secp256k1.rs: **62.75%** (개선 중)
- ⚠️ crypto/keys.rs: **66.19%**
- ⚠️ blockchain/ownership.rs: **65.89%**

---

## 🎯 Priority Tasks

### P1-HIGH: 핵심 기능 테스트 보강

#### Task H-1: RFC 9421 HTTP Signatures Testing
**Priority**: P1-HIGH
**Module**: `rfc9421/`
**Current Coverage**:
- verifier.rs: 5.90%
- mod.rs: 7.55%
- canonicalize.rs: 58.15%
- signer.rs: 58.49%

**Goal**: 80%+ coverage

**Tasks**:
- [ ] HTTP 서명 검증 테스트 (verifier.rs)
- [ ] 정규화(canonicalization) 테스트
- [ ] 서명 생성 엣지 케이스
- [ ] 다양한 HTTP 메서드 테스트
- [ ] 헤더 파싱 테스트

**Expected Impact**: HTTP Message Signatures 기능 안정화

---

#### Task H-2: Blockchain Client Integration Tests
**Priority**: P1-HIGH
**Module**: `blockchain/ethereum/`, `blockchain/solana/`
**Current Coverage**:
- ethereum/client.rs: 6.45%
- ethereum/resolver.rs: 14.75%

**Goal**: 50%+ coverage (통합 테스트 특성상)

**Tasks**:
- [ ] Mock RPC 테스트 환경 구축
- [ ] Agent 등록 테스트
- [ ] Agent 조회 테스트
- [ ] 키 관리 테스트
- [ ] 에러 처리 테스트

**Expected Impact**: 블록체인 통합 안정성 향상

---

#### Task H-3: Key Format Conversion Testing
**Priority**: P1-HIGH
**Module**: `formats/mod.rs`
**Current Coverage**: 55.84%

**Goal**: 80%+ coverage

**Tasks**:
- [ ] JWK export/import 테스트
- [ ] PEM export/import 테스트
- [ ] DER format 테스트
- [ ] 알고리즘별 변환 테스트
- [ ] 에러 케이스 테스트

**Expected Impact**: 키 포맷 변환 신뢰성 향상

---

### P2-MEDIUM: 코드 품질 개선

#### Task M-1: Remove Unused Imports
**Priority**: P2-MEDIUM
**Effort**: 15min

**Tasks**:
- [ ] keys.rs: `ToEncodedPoint` 제거
- [ ] p256.rs: `ToEncodedPoint` 제거
- [ ] `cargo fix` 실행

**Expected Impact**: 클린 빌드

---

#### Task M-2: Core Module Coverage Improvement
**Priority**: P2-MEDIUM
**Module**: `core/`
**Current Coverage**:
- verification_service.rs: 50.00%
- message.rs: 89.09%

**Goal**: 80%+ coverage

**Tasks**:
- [ ] Verification service 테스트
- [ ] Message validation 테스트
- [ ] 에러 시나리오 테스트

---

#### Task M-3: Crypto Keys Testing
**Priority**: P2-MEDIUM
**Module**: `crypto/keys.rs`
**Current Coverage**: 66.19%

**Goal**: 85%+ coverage

**Tasks**:
- [ ] KeyPair 변환 테스트
- [ ] 다양한 KeyType 테스트
- [ ] 에러 처리 테스트
- [ ] 직렬화/역직렬화 테스트

---

### P3-LOW: 선택적 개선

#### Task L-1: Documentation Expansion
**Priority**: P3-LOW

**Tasks**:
- [ ] RFC 9421 HTTP Signatures 가이드
- [ ] Blockchain Integration 업데이트
- [ ] API Reference 완성
- [ ] Architecture 다이어그램

---

#### Task L-2: Performance Benchmarks
**Priority**: P3-LOW

**Tasks**:
- [ ] X25519 vs ECDH 벤치마크
- [ ] Multi-Chain Manager 성능
- [ ] 알고리즘별 서명/검증 속도
- [ ] 메모리 사용량 프로파일링

---

#### Task L-3: Integration Examples
**Priority**: P3-LOW

**Tasks**:
- [ ] End-to-end 예제
- [ ] Multi-chain agent 등록
- [ ] Encrypted communication channel
- [ ] Key rotation workflow

---

## 🎯 Target Metrics

### Coverage Goals
- **Current**: 73.49%
- **Phase Target**: **80%+**
- **Critical Modules**: 85%+

### Test Goals
- **Current**: 250 tests
- **Phase Target**: **300+ tests** (+50)

### Quality Goals
- **Build Warnings**: 0
- **Clippy Warnings**: 0
- **Documentation**: 100% public APIs

---

## 📅 Suggested Prioritization

### Week 1: HTTP Signatures & Critical Tests
1. Task H-1: RFC 9421 Testing (3-4 days)
2. Task M-1: Remove unused imports (0.5 day)
3. Task M-2: Core module coverage (1-2 days)

**Deliverable**: +30 tests, HTTP Signatures stable

---

### Week 2: Blockchain Integration & Key Formats
1. Task H-2: Blockchain client tests (3-4 days)
2. Task H-3: Format conversion tests (2-3 days)

**Deliverable**: +25 tests, blockchain integration stable

---

### Week 3: Quality & Documentation
1. Task M-3: Crypto keys testing (2 days)
2. Task L-1: Documentation expansion (2-3 days)
3. Task L-2: Performance benchmarks (optional)

**Deliverable**: 80%+ coverage, complete documentation

---

## 🔧 Quick Wins (1-2 hours)

1. **Remove unused imports** (Task M-1)
   ```bash
   cargo fix --lib -p sage_crypto_core
   ```

2. **Add basic HTTP signature tests**
   - Test signature generation
   - Test verification happy path

3. **Complete secp256k1 & signature tests**
   - Already in progress, add 5-10 more tests

---

## 📊 Progress Tracking

### Phase Completion Criteria
- [ ] 80%+ overall coverage
- [ ] 300+ tests passing
- [ ] 0 build warnings
- [ ] All P1-HIGH tasks complete
- [ ] Documentation for new features

### Success Metrics
- Coverage: 73.49% → 80%+
- Tests: 250 → 300+
- Critical bugs: 0
- Documentation completeness: 100%

---

## 🚀 Getting Started

### Immediate Next Steps

1. **Run cleanup**:
   ```bash
   cargo fix --lib -p sage_crypto_core
   cargo clippy --fix --lib --features blockchain
   ```

2. **Start with HTTP Signatures** (highest impact):
   ```bash
   # Create test file
   touch src/rfc9421/verifier_tests.rs

   # Add tests for:
   # - Signature verification
   # - Header parsing
   # - Canonicalization
   ```

3. **Set up coverage tracking**:
   ```bash
   cargo llvm-cov --lib --features blockchain --html
   open target/llvm-cov/html/index.html
   ```

---

## 📝 Notes

- **X25519**: 99.07% coverage - excellent! 🎉
- **Multi-Chain Manager**: New module, tests needed
- **Signature.rs**: Improved from 21.43%, continue enhancement
- **Secp256k1.rs**: Improved from 62.75%, continue enhancement
- **Focus**: HTTP Signatures & Blockchain clients (lowest coverage)

---

**Prepared by**: Claude Code
**Date**: 2025-10-28
**Version**: rs-sage-core v0.3.0
